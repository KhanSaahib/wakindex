"""Description: Tests for capability policy validation, precedence, matching, and budgets."""

import copy
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from wakindex.capability_policy import (
    Decision,
    PolicyInvalid,
    PolicySchemaIncompatible,
    Request,
    canonical_path,
    evaluate,
    explain,
    path_within,
    validate_revision,
)

FIXTURES = Path(__file__).parent / "fixtures" / "contracts"


def base_document(**overrides):
    document = {
        "schema_version": "1.0",
        "revision": 4,
        "parent_revision": 3,
        "created_at": "2026-09-20T17:38:00Z",
        "created_by": "principal:uid:1000",
        "rules": [
            {
                "id": "r-fs-project",
                "effect": "allow",
                "capability": "file.read",
                "match": {"path_prefix": "/home/op/project"},
                "reason_code": "ALLOW_RULE",
            }
        ],
        "budgets": {"pids": 256},
    }
    document.update(overrides)
    return document


def request(capability="file.read", resource="resource:file:/home/op/project/README.md", **kwargs):
    return Request("s:test", capability, resource, **kwargs)


# -- ALP-200: validation ---------------------------------------------------------------------


def test_a_valid_document_produces_a_revision():
    revision = validate_revision(base_document())
    assert revision.revision == 4
    assert len(revision.rules) == 1


@pytest.mark.parametrize(
    "where",
    [
        "top-level",
        "rule",
        "match",
        "budgets",
    ],
)
def test_an_unknown_field_is_an_error_not_an_ignored_key(where):
    """A misspelled key must never become a permitted-by-omission gap."""
    document = base_document()
    if where == "top-level":
        document["deny_all"] = True
    elif where == "rule":
        document["rules"][0]["efect"] = "deny"
    elif where == "match":
        document["rules"][0]["match"]["path_preix"] = "/etc"
    else:
        document["budgets"]["cpu"] = 1

    with pytest.raises(PolicyInvalid, match="unknown field"):
        validate_revision(document)


def test_a_misspelled_deny_effect_is_rejected_rather_than_read_as_allow():
    document = base_document()
    document["rules"][0]["effect"] = "denyy"
    with pytest.raises(PolicyInvalid, match="effect must be"):
        validate_revision(document)


def test_one_invalid_rule_rejects_the_whole_revision():
    """A partially loaded policy is a gap with no operator able to see it."""
    document = base_document()
    document["rules"].append(
        {
            "id": "r-bad",
            "effect": "deny",
            "capability": "file.teleport",
            "match": {"any": True},
            "reason_code": "DENY_EXPLICIT_RULE",
        }
    )
    with pytest.raises(PolicyInvalid, match="capability must be"):
        validate_revision(document)


def test_a_rule_whose_reason_contradicts_its_effect_is_rejected():
    """A rule that says ALLOW_RULE while denying would explain a decision it did not make."""
    document = base_document()
    document["rules"][0]["effect"] = "deny"
    with pytest.raises(PolicyInvalid, match="requires reason_code"):
        validate_revision(document)


def test_duplicate_rule_ids_are_rejected():
    document = base_document()
    document["rules"].append(copy.deepcopy(document["rules"][0]))
    with pytest.raises(PolicyInvalid, match="duplicate rule id"):
        validate_revision(document)


def test_a_different_schema_major_fails_closed():
    with pytest.raises(PolicySchemaIncompatible):
        validate_revision(base_document(schema_version="2.0"))


def test_an_additive_minor_version_is_accepted():
    assert validate_revision(base_document(schema_version="1.7")).schema_version == "1.7"


@pytest.mark.parametrize(
    "match",
    [
        {},
        {"any": False},
        {"any": True, "path": "/etc"},
        {"path": "relative/path"},
        {"path": "/a\x00b"},
        {"path": 5},
        {"path": "/a", "path_prefix": "/b"},
        {"host": ""},
    ],
)
def test_a_selector_that_cannot_be_understood_is_rejected(match):
    document = base_document()
    document["rules"][0]["match"] = match
    with pytest.raises(PolicyInvalid):
        validate_revision(document)


@pytest.mark.parametrize("budget", [{"pids": -1}, {"pids": "many"}, {"pids": True}])
def test_a_budget_that_is_not_a_count_is_rejected(budget):
    with pytest.raises(PolicyInvalid, match="budgets"):
        validate_revision(base_document(budgets=budget))


def test_parent_revision_must_precede_the_revision():
    with pytest.raises(PolicyInvalid, match="parent_revision"):
        validate_revision(base_document(revision=3, parent_revision=3))


# -- ALP-200: immutability and digest ----------------------------------------------------------


def test_a_revision_cannot_be_mutated_in_place():
    revision = validate_revision(base_document())
    with pytest.raises(FrozenInstanceError):
        revision.revision = 5  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        revision.rules[0].effect = "deny"  # type: ignore[misc]


def test_a_rules_match_mapping_cannot_be_mutated_in_place():
    """`frozen=True` blocks reassigning `rule.match`; it does nothing to its contents.

    Regression: `Rule.match` used to be a plain `dict`, so `rule.match["path_prefix"] = "/"`
    succeeded silently -- no FrozenInstanceError, nothing -- and changed what the rule matches
    for every holder of the object. Demonstrated end to end: a deny of /etc/shadow flips to an
    allow with no error raised anywhere.
    """
    revision = validate_revision(base_document())
    deny = evaluate(revision, request(resource="resource:file:/etc/shadow"))
    assert deny.effect == "deny"

    with pytest.raises(TypeError):
        revision.rules[0].match["path_prefix"] = "/"

    still_denied = evaluate(revision, request(resource="resource:file:/etc/shadow"))
    assert still_denied.effect == "deny"


def test_a_revisions_budget_limits_cannot_be_mutated_in_place():
    """Same gap, same fix, for `Budgets.limits`."""
    revision = validate_revision(base_document())

    with pytest.raises(TypeError):
        revision.budgets.limits["pids"] = 999_999_999

    assert revision.budgets.limits["pids"] == 256


def test_the_digest_is_stable_across_key_order_and_whitespace():
    """Two spellings of the same policy are the same policy, and must digest identically."""
    first = validate_revision(base_document())
    reordered = json.loads(json.dumps(base_document(), sort_keys=True, indent=4))
    second = validate_revision(reordered)
    assert first.revision_digest == second.revision_digest


def test_the_digest_changes_when_a_rule_changes():
    first = validate_revision(base_document())
    document = base_document()
    document["rules"][0]["match"]["path_prefix"] = "/home/op/other"
    assert validate_revision(document).revision_digest != first.revision_digest


def test_mutating_the_source_document_does_not_change_the_revision():
    """The revision must not alias the caller's dict, or it is immutable in name only."""
    document = base_document()
    revision = validate_revision(document)
    digest = revision.revision_digest

    document["rules"][0]["match"]["path_prefix"] = "/"
    document["budgets"]["pids"] = 999999

    assert revision.revision_digest == digest


# -- ALP-201: precedence -----------------------------------------------------------------------


def test_no_matching_rule_denies_by_default():
    """Absence is never permission."""
    revision = validate_revision(base_document(rules=[]))
    decision = evaluate(revision, request())

    assert decision.effect == "deny"
    assert decision.reason_code == "DENY_DEFAULT"
    assert decision.matched_rule_id is None


def test_a_matching_allow_allows():
    decision = evaluate(validate_revision(base_document()), request())
    assert decision.effect == "allow"
    assert decision.matched_rule_id == "r-fs-project"


def test_a_broad_deny_beats_a_more_specific_allow():
    """The intuitive rule in most policy systems is the opposite. It is not the rule here."""
    document = base_document(
        rules=[
            {
                "id": "r-deny-all",
                "effect": "deny",
                "capability": "file.read",
                "match": {"any": True},
                "reason_code": "DENY_EXPLICIT_RULE",
            },
            {
                "id": "r-allow-exact",
                "effect": "allow",
                "capability": "file.read",
                "match": {"path": "/home/op/project/README.md"},
                "reason_code": "ALLOW_RULE",
            },
        ]
    )
    decision = evaluate(validate_revision(document), request())

    assert decision.effect == "deny"
    assert decision.reason_code == "DENY_EXPLICIT_RULE"
    assert decision.matched_rule_id == "r-deny-all"


def test_specificity_names_the_rule_but_does_not_change_the_outcome():
    document = base_document(
        rules=[
            {
                "id": "r-a-broad",
                "effect": "deny",
                "capability": "file.read",
                "match": {"path_prefix": "/home"},
                "reason_code": "DENY_EXPLICIT_RULE",
            },
            {
                "id": "r-z-narrow",
                "effect": "deny",
                "capability": "file.read",
                "match": {"path_prefix": "/home/op/project"},
                "reason_code": "DENY_EXPLICIT_RULE",
            },
        ]
    )
    decision = evaluate(validate_revision(document), request())

    assert decision.effect == "deny"
    assert decision.matched_rule_id == "r-z-narrow"


def test_rule_naming_is_total_so_two_evaluators_cannot_disagree():
    """Equally specific rules tie-break on id, not on document order."""
    rules = [
        {
            "id": f"r-{suffix}",
            "effect": "deny",
            "capability": "file.read",
            "match": {"path_prefix": "/home/op"},
            "reason_code": "DENY_EXPLICIT_RULE",
        }
        for suffix in ("zzz", "aaa", "mmm")
    ]
    forward = evaluate(validate_revision(base_document(rules=rules)), request())
    reversed_ = evaluate(validate_revision(base_document(rules=rules[::-1])), request())

    assert forward.matched_rule_id == "r-aaa"
    assert reversed_.matched_rule_id == "r-aaa"


def test_a_rule_for_another_capability_does_not_match():
    document = base_document()
    document["rules"][0]["capability"] = "file.write"
    decision = evaluate(validate_revision(document), request(capability="file.read"))

    assert decision.reason_code == "DENY_DEFAULT"


def test_every_decision_binds_to_the_revision_that_produced_it():
    revision = validate_revision(base_document())
    decision = evaluate(revision, request())

    assert decision.policy_revision == revision.revision
    assert decision.revision_digest == revision.revision_digest
    assert decision.session_id == "s:test"


def test_repeated_evaluation_is_byte_identical():
    revision = validate_revision(base_document())
    first = evaluate(revision, request())
    second = evaluate(revision, request())
    assert json.dumps(first.as_dict(), sort_keys=True) == json.dumps(
        second.as_dict(), sort_keys=True
    )


def test_a_decision_record_carries_no_timestamp_or_identifier_of_its_own():
    """Decisions must compare equal across runs; the supervisor stamps id and time."""
    fields = set(evaluate(validate_revision(base_document()), request()).as_dict())
    assert "evaluated_at" not in fields
    assert "decision_id" not in fields


def test_an_advisory_decision_is_labelled_as_such():
    decision = evaluate(validate_revision(base_document()), request(), enforcement="advisory")
    assert decision.enforcement == "advisory"


def test_there_is_no_model_inference_in_the_authorization_path():
    """An authorization decision that cannot be reproduced from the revision is not one."""
    import ast

    source = Path(__file__).parent.parent / "src" / "wakindex" / "capability_policy.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    forbidden = {"anthropic", "openai", "requests", "httpx", "urllib", "socket", "random"}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] not in forbidden
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module.split(".")[0] not in forbidden


# -- ALP-202: canonical matching ---------------------------------------------------------------


def test_a_sibling_directory_sharing_a_name_prefix_is_not_inside():
    """The bug this matching exists to prevent: /home/op/project-secrets is not in project."""
    decision = evaluate(
        validate_revision(base_document()),
        request(resource="resource:file:/home/op/project-secrets/key.pem"),
    )
    assert decision.effect == "deny"
    assert decision.reason_code == "DENY_DEFAULT"


def test_the_prefix_directory_itself_matches():
    decision = evaluate(
        validate_revision(base_document()), request(resource="resource:file:/home/op/project")
    )
    assert decision.effect == "allow"


@pytest.mark.parametrize(
    "resource",
    [
        "resource:file:/home/op/project//README.md",
        "resource:file:/home/op/project/./README.md",
        "resource:file:/home/op/project/sub/../README.md",
        "resource:file:/home/op/other/../project/README.md",
    ],
)
def test_equivalent_spellings_of_a_path_all_match(resource):
    decision = evaluate(validate_revision(base_document()), request(resource=resource))
    assert decision.effect == "allow"


def test_traversal_out_of_the_prefix_does_not_match():
    decision = evaluate(
        validate_revision(base_document()),
        request(resource="resource:file:/home/op/project/../../etc/shadow"),
    )
    assert decision.effect == "deny"


def test_a_resource_that_cannot_be_canonicalized_is_denied_not_matched_loosely():
    document = base_document(
        rules=[
            {
                "id": "r-any-read",
                "effect": "allow",
                "capability": "file.read",
                "match": {"path_prefix": "/"},
                "reason_code": "ALLOW_RULE",
            }
        ]
    )
    decision = evaluate(validate_revision(document), request(resource="resource:file:relative"))
    assert decision.effect == "deny"


@pytest.mark.parametrize(
    ("candidate", "prefix", "expected"),
    [
        ("/a/b", "/a", True),
        ("/a", "/a", True),
        ("/ab", "/a", False),
        ("/a/b", "/a/", True),
        ("/", "/", True),
        ("/a", "/a/b", False),
    ],
)
def test_path_within_compares_segments(candidate, prefix, expected):
    assert path_within(candidate, prefix) is expected


@pytest.mark.parametrize("raw", ["relative", "", "./a", "a/../b", "/a\x00b", None, 7])
def test_canonical_path_rejects_what_it_cannot_reduce(raw):
    assert canonical_path(raw) is None


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/..", "/"),
        ("/../etc", "/etc"),
        ("/../../etc/shadow", "/etc/shadow"),
        ("/a/b/../../c", "/c"),
    ],
)
def test_traversal_above_root_clamps_to_root_as_the_kernel_does(raw, expected):
    """POSIX resolves `..` at root to root, so the kernel reads /../etc as /etc.

    Normalizing the same way is what keeps matching honest: the evaluator and the kernel must
    agree on which file a path names, or a rule protects a path nobody is actually opening.
    """
    assert canonical_path(raw) == expected


def test_a_tool_rule_matches_tool_and_method():
    document = base_document(
        rules=[
            {
                "id": "r-tool-fmt",
                "effect": "allow",
                "capability": "tool.invoke",
                "match": {"tool": "fs", "method": "format"},
                "reason_code": "ALLOW_RULE",
            }
        ]
    )
    revision = validate_revision(document)

    allowed = evaluate(revision, request("tool.invoke", "tool_server:mcp:fs#format"))
    denied = evaluate(revision, request("tool.invoke", "tool_server:mcp:fs#delete"))

    assert allowed.effect == "allow"
    assert denied.reason_code == "DENY_DEFAULT"


def test_a_host_rule_matches_the_host_without_the_port():
    document = base_document(
        rules=[
            {
                "id": "r-net",
                "effect": "allow",
                "capability": "net.connect",
                "match": {"host": "10.0.0.5"},
                "reason_code": "ALLOW_RULE",
            }
        ]
    )
    revision = validate_revision(document)

    assert evaluate(revision, request("net.connect", "resource:net:tcp/10.0.0.5:443")).effect == (
        "allow"
    )
    assert evaluate(revision, request("net.connect", "resource:net:tcp/10.0.0.6:443")).effect == (
        "deny"
    )


# -- ALP-202: budgets --------------------------------------------------------------------------


def test_an_exceeded_budget_denies_even_when_a_rule_allows():
    revision = validate_revision(base_document())
    decision = evaluate(revision, request(usage={"pids": 256}))

    assert decision.effect == "deny"
    assert decision.reason_code == "DENY_BUDGET_EXCEEDED"


def test_usage_below_the_limit_does_not_deny():
    revision = validate_revision(base_document())
    assert evaluate(revision, request(usage={"pids": 255})).effect == "allow"


def test_a_budget_the_caller_did_not_report_is_not_assumed_to_be_zero():
    """The evaluator reads no clock and no counter; an unreported budget is simply not checked."""
    revision = validate_revision(base_document())
    assert evaluate(revision, request(usage={})).effect == "allow"


def test_the_first_exceeded_limit_is_deterministic():
    revision = validate_revision(base_document(budgets={"pids": 1, "cpu_ms": 1}))
    first = evaluate(revision, request(usage={"pids": 9, "cpu_ms": 9}))
    second = evaluate(revision, request(usage={"cpu_ms": 9, "pids": 9}))
    assert first.as_dict() == second.as_dict()


# -- explain ------------------------------------------------------------------------------------


def test_explain_lists_every_matching_rule_not_only_the_named_one():
    """An operator who removes the named rule and sees no change needs to know why."""
    document = base_document(
        rules=[
            {
                "id": "r-broad",
                "effect": "deny",
                "capability": "file.read",
                "match": {"path_prefix": "/home"},
                "reason_code": "DENY_EXPLICIT_RULE",
            },
            {
                "id": "r-narrow",
                "effect": "deny",
                "capability": "file.read",
                "match": {"path_prefix": "/home/op/project"},
                "reason_code": "DENY_EXPLICIT_RULE",
            },
        ]
    )
    result = explain(validate_revision(document), request())

    assert result["decision"]["matched_rule_id"] == "r-narrow"
    assert [rule["id"] for rule in result["matched_rules"]] == ["r-broad", "r-narrow"]


def test_explain_has_no_side_effects():
    revision = validate_revision(base_document())
    before = revision.revision_digest
    explain(revision, request())
    assert revision.revision_digest == before


# -- ALP-203: golden fixtures --------------------------------------------------------------------


def load_fixture(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_g2_cases_match_their_recorded_expectations():
    """Checked against the approved fixture so code and fixture cannot drift into agreement."""
    fixture = load_fixture("g2-precedence-conflict.json")
    revision = validate_revision(fixture["policy"])

    for case in fixture["cases"]:
        decision = evaluate(revision, request(case["capability"], case["resource"]))
        expected = case["expected"]
        assert decision.effect == expected["effect"], case["name"]
        assert decision.reason_code == expected["reason_code"], case["name"]
        assert decision.matched_rule_id == expected["matched_rule_id"], case["name"]


def test_g3_cases_match_their_recorded_expectations():
    fixture = load_fixture("g3-deny-beats-specificity.json")
    revision = validate_revision(fixture["policy"])

    for case in fixture["cases"]:
        decision = evaluate(revision, request(case["capability"], case["resource"]))
        expected = case["expected"]
        assert decision.effect == expected["effect"], case["name"]
        assert decision.reason_code == expected["reason_code"], case["name"]
        assert decision.matched_rule_id == expected["matched_rule_id"], case["name"]


def test_g2_variants_from_the_contract_hold():
    """Removing r-fs-secrets allows; removing both denies by default."""
    fixture = load_fixture("g2-precedence-conflict.json")
    secret_request = request("file.read", "resource:file:/home/op/project/.env")

    without_deny = copy.deepcopy(fixture["policy"])
    without_deny["rules"] = [r for r in without_deny["rules"] if r["id"] != "r-fs-secrets"]
    decision = evaluate(validate_revision(without_deny), secret_request)
    assert (decision.effect, decision.matched_rule_id) == ("allow", "r-fs-project")

    without_both = copy.deepcopy(without_deny)
    without_both["rules"] = [r for r in without_both["rules"] if r["id"] != "r-fs-project"]
    decision = evaluate(validate_revision(without_both), secret_request)
    assert (decision.effect, decision.reason_code) == ("deny", "DENY_DEFAULT")


def test_decision_is_a_frozen_record():
    decision = evaluate(validate_revision(base_document()), request())
    assert isinstance(decision, Decision)
    with pytest.raises(FrozenInstanceError):
        decision.effect = "allow"  # type: ignore[misc]
