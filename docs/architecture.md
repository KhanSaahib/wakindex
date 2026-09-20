# wakindex Architecture

## Description

This document defines wakindex's system boundaries, workspace and endpoint data flow, security
invariants, normalized data model, policy semantics, and extension contract.

## Goals and non-goals

wakindex answers seven pre-execution questions:

1. Which agent and MCP configurations are present in a workspace or known user locations?
2. Which processes, tools, and network endpoints can those configurations invoke?
3. Which files, credential names, approval modes, and GitHub token permissions can they reach?
4. Which normalized permissions and concrete resources does that imply?
5. Does the inventory comply with a reviewable local policy?
6. Which explicit human, service, or shared account owns each agent configuration?
7. Which configured model, model provider, provider-account alias, and safe authentication context
   are associated with that access?

wakindex is a static reviewer. It does not execute agents or MCP servers, fetch remote tool
descriptions, resolve live cloud IAM, validate downloaded packages, prove runtime behavior, or
replace sandboxing and identity controls.

The identity inventory is configuration evidence rather than runtime attestation. A configured
model may be overridden by a command-line flag, environment variable, managed setting, or active
session. A provider-account alias is an operator assertion and is not proof of a live login.

## Trust and privacy boundaries

The workspace and discovered configuration files are untrusted. JSON, TOML, Markdown, paths,
workflow YAML, and environment references may be intentionally malicious. The policy and wakindex
process are trusted inputs controlled by the reviewer.

Security invariants:

- discovered commands are represented as evidence and never executed;
- credential and environment-variable names may be recorded, but values are never emitted;
- embedded-credential detection reports only the containing field name;
- repository discovery does not traverse symlinks outside the scan root;
- user discovery checks a fixed path allowlist, skips symlinks, and never crawls the profile;
- user sources use stable `user/...` labels and redact the audited home prefix;
- account catalogs are explicit trusted input and profile home paths are never serialized;
- model/auth extraction reads only documented non-secret fields and safe credential names;
- manifest ordering is deterministic and excludes runtime timestamps;
- every matching deny takes precedence over every allow;
- the policy editor binds only to `127.0.0.1` and preserves scoped policy rules;
- the identity dashboard is read-only, loopback-only, same-origin, and never embeds hostile
  inventory values in executable JavaScript;
- malformed policy input fails closed with a diagnostic rather than a traceback.

## Processing pipeline

```text
workspace root -----------------> repository candidate discovery
        |                                      |
        |                                      v
        |                             format-specific scanners
        |                                      |
explicit audit command                         |
        |                                      |
        v                                      |
known user config paths --> privacy context -->+--> normalized Finding values
                                                        |
                                                        v
                                              deterministic Manifest
                                                 /             \
                                                v               v
                                         JSON / text / SARIF   policy v1
                                                                  |
                                                                  v
                                                          pass or violations

explicit account catalog ---> account/profile boundaries
          |                              |
          |                              v
          +------------------> config identity inspection
                                         |
Manifest findings + policy decisions ----+--> identity-1.0 relationship inventory
                                                        |
                                                        +--> JSON / text
                                                        |
                                                        +--> loopback dashboard
```

`scan` uses only the workspace path. `audit` includes known user configuration. `check` remains
workspace-only unless `--include-user` is explicit.

## Component responsibilities

| Component | Responsibility | Must not do |
| --- | --- | --- |
| `environment.py` | Discover known user config paths and combine endpoint findings | Crawl the home directory or emit its absolute prefix |
| `scanners.py` | Extract static evidence from supported files | Execute commands, emit credential values, or escape the boundary |
| `models.py` | Define stable `Finding` and `Manifest` serialization | Add volatile runtime state |
| `identity.py` | Validate account catalogs and build account/agent/model/access relationships | Read token stores or claim runtime identity |
| `policy.py` | Validate TOML and apply legacy/scoped deny precedence | Infer intent or silently accept malformed rules |
| `sarif.py` | Translate violations to SARIF 2.1 | Change policy decisions |
| `cli.py` | Validate arguments, select scan scope/output, and return stable exit codes | Pollute JSON or SARIF stdout |
| `ui.py` | Edit legacy permission choices on loopback while preserving scoped rules | Contact remote services |
| `dashboard.py` | Serve an immutable relationship inventory with safe browser filtering/export | Bind externally or interpolate hostile HTML |
| `release.py` | Match immutable SemVer tags to the package version | Publish or mutate tags |

## Discovery scopes

Workspace discovery recursively considers only supported filenames and GitHub workflow locations,
subject to `.wakindexignore`. User discovery does not recurse and considers:

- Codex `~/.codex/config.toml`;
- Claude Code `~/.claude/settings.json` and MCP data in `~/.claude.json`;
- Cursor `~/.cursor/mcp.json`;
- Gemini CLI `~/.gemini/settings.json`;
- platform-specific VS Code user `mcp.json`;
- platform-specific Claude Desktop `claude_desktop_config.json`.

An explicit `--home` makes the user boundary reproducible for containers and endpoint management.
System-level MDM, registry, and fleet APIs are not scanned in this milestone.

Multi-account inventory uses explicit account-catalog homes and runs the same fixed known-path
discovery independently for each account. The current-account workflow does not enumerate other
operating-system users.

## Data model and compatibility

A finding contains:

- a normalized permission ID such as `process.execute`;
- a concrete resource, normally the server, tool, or token identity;
- a repository-relative or stable `user/...` source;
- bounded, value-safe human-readable evidence;
- a `low`, `medium`, or `high` risk;
- structured metadata for policy selectors.

New findings include `provider` and `scope` metadata. Capability-specific metadata includes
`server`, `command`, `host`, `environment_variable`, `path`, `approval_mode`, and
`github_scope`. Vendor-specific details stay in metadata rather than the core manifest shape.

Manifest schema `1.0` remains independent from the package version. Adding metadata keys or new
permission IDs is backward compatible. Removing fields, changing existing permission meaning, or
altering stable source semantics requires a new schema version and migration guidance.

Identity inventory schema `identity-1.0` is separate and contains accounts, agent instances, and
access records. Account home paths are runtime scan boundaries and are intentionally absent from
serialization. Each access record retains the underlying normalized finding and adds account ID,
agent ID, and an `allowed`, `denied`, or `unreviewed` policy decision.

An agent instance corresponds to one account plus one supported configuration source. Its stable
ID is derived deterministically from endpoint, workspace identifier, account ID, provider, and
source so inventories can be merged across a fleet without common project-path collisions. Model
status is either `configured` or `runtime-selected`; missing information is not guessed.

## Access graph and snapshot store

The access graph is a separate runtime schema from the manifest above, with its own records, its
own version, and its own parser. It describes what a supervised agent session can reach, not what
a repository declares, and the two must not be merged: overloading one schema with both would make
a static configuration finding indistinguishable from an enforced boundary.

A finding is an edge — subject, relation, object — carrying provenance, confidence, freshness and
enforcement status. `classification` records how the access was learned:

- `declared` — read from configuration. Not evidence that the access works.
- `observed` — seen in use. Not evidence of the full extent of the permission.
- `inferred` — derived reachability. Not evidence that the far side would authorize the call.
- `enforced` — a boundary is installed for the named policy revision.

Only `enforced` supports a negative claim, so `AccessFinding` refuses to be constructed with
classification `enforced` unless the enforcement status agrees.

A scope a collector could not read is recorded as an `AccessUnknown`, never as an omission.
Unknowns carry a code such as `collector_permission_denied` and a relation-plus-prefix scope.

A snapshot separates a normalized form from an evidence sidecar. The normalized form holds only
stable fields, sorted by finding ID, so two scans of an unchanged environment produce identical
bytes; timestamps, descriptors and evidence bodies live in the sidecar and never move a diff.

`diff(before, after)` returns `added`, `removed`, `changed` and `indeterminate`. A finding missing
from the later snapshot is `removed` only when no unknown in that snapshot covers its scope;
otherwise it is `indeterminate`. Reporting a collector failure as revoked access would tell an
operator that a permission is gone when it may still be there.

`GraphStore` persists snapshots in SQLite with versioned migrations. Each snapshot is written in
one transaction, so a failed write leaves no snapshot that is missing its unknowns and therefore
reads as a complete scan. A migration that would reduce the stored evidence count is rolled back,
and a store written by a newer build is refused rather than read on a guess.

Evidence and unknown detail are checked against credential-shaped patterns on construction. A
value that looks like a secret fails the write rather than being persisted and redacted later.

## Access collectors

Collectors populate the access graph from a running process tree. They read process metadata
under `/proc` and nothing else: opening a discovered file to learn more about it would make a
collector an execution path for whatever wrote that file, and an inherited descriptor is exactly
what an adversary would point at something it wants read.

The framework, not each collector, enforces the budget. Findings are capped, per-scope
enumeration is capped, and a pass that runs past its deadline records a timeout instead of
continuing. Every failure becomes an `AccessUnknown` over the scope that failed, because a scope
nobody looked at is otherwise indistinguishable from a scope with nothing in it. Each collector
declares the scopes it owns, so a collector that fails outright leaves those scopes marked unseen
rather than leaving its findings uncovered.

`PrincipalCollector` records real, effective, saved and filesystem uid and gid separately, plus
supplementary groups and the effective capability mask. An unreadable capability line is an
unknown, never an empty set: an empty set means the process holds nothing, and reporting an
unreadable one that way understates what the process can do. When the process shares the
operator's effective uid it records that as a finding, because the containment story does not
apply to that profile at all.

`LineageCollector` walks the tree and records descendants, working directory, root and inherited
descriptors. A process that exits mid-walk is recorded as an unknown rather than dropped — it
existed, and a reader judging whether the tree was contained needs to know. A tree that grows
during the walk records a `partial_enumeration`, so an agent that forks while being read cannot
hide a descendant for free. Descriptor targets are read as link targets only and reported as the
kernel gives them, including a `(deleted)` marker; reconstructing a path after a rename would
name a file that may now be something else.

`MountCollector` records mount points, sources, filesystem types, read-only status and
propagation mode. Propagation matters because a shared mount can carry a mount created on the
host into the perimeter after launch, so a boundary complete at launch may not stay that way. An
unreadable mount table is an unknown over the whole filesystem scope, never an empty mount list.

`NetworkCollector` records sockets and routes, and the split between them is the point. An
established connection or a listening socket is `observed`. A destination reachable only because
a route exists is `inferred` with low confidence, and its evidence says the connection was not
attempted and says nothing about whether the far side would authorize it. The absence of a
default route is recorded as its own finding rather than as an empty section, because an empty
network section reads like a collector that did not run. Addresses are decoded from little-endian
`/proc/net` words; an address that cannot be decoded exactly becomes an unknown, since a wrong
destination in an access inventory is worse than a missing one. The collector opens no connection
and resolves no name: probing would make the inventory generate the traffic it exists to describe.

`ToolCollector` records configured tool and MCP servers by delegating to the repository's existing
configuration scanner rather than adding a second parser for the same formats. Everything it
produces is `declared`: a configuration file says what was asked for, not what happened. A
discovered command is recorded as text and never run. A file that is missing, malformed or empty
becomes an unknown, because a file that could not be parsed and an agent that reaches nothing must
not look the same.

`CredentialCollector` records credential references by name and path and never their values.
`/proc/<pid>/environ` is split on the first `=` and the value discarded immediately; credential
files are checked for existence and never opened. Every finding states that what the credential
authorizes remotely is unknown, because holding a token is not evidence of its scope and an
offline host cannot ask the issuer. The canary tests search the serialized snapshot, the evidence
sidecar and the database file for a planted secret rather than inspecting individual fields, so a
leak through a field added later still fails.

None of these collectors installs or inspects an enforcement boundary, so every finding they
produce carries enforcement status `unknown`.

## Permission taxonomy

Current permission IDs:

- `process.execute` and `process.shell`;
- `filesystem.read`, `filesystem.write`, and `filesystem.outside_workspace`;
- `network.access`;
- `secrets.inherit` and `secrets.embedded`;
- `github.token`;
- `agent.auto_approve` and `agent.unrestricted`.

`secrets.embedded` means a sensitive field contains literal material; the value is discarded.
`agent.auto_approve` is narrower than unrestricted host access and identifies confirmation bypass
at either agent or MCP-server scope.

## Policy model

Policy version 1 supports legacy permission-wide `allow` and `deny` patterns plus named rules that
match permission, resource, source, risk, and metadata. Matching is case-sensitive and uses
shell-style wildcards.

Evaluation order is legacy deny, scoped deny, legacy allow, scoped allow, then default. Duplicate
rule IDs, unknown rule fields, unsupported versions, and non-string selectors are invalid.
`docs/policy.md` is the public schema contract.

## Supported inputs

- Claude-style `.claude/settings.json`, `.claude/settings.local.json`, and `.claude.json`;
- Codex `.codex/config.toml` and user `~/.codex/config.toml`;
- VS Code, Cursor, Gemini, Claude Desktop, and generic MCP JSON;
- `.agents/skills/**/SKILL.md`, `.claude/skills/**/SKILL.md`, and `skills/**/SKILL.md`;
- `.github/workflows/*.yml` and `*.yaml`;
- `${NAME}`, `$NAME`, and `%NAME%` environment references;
- Codex `env_vars`, bearer-token variables, and environment-backed HTTP headers.

Repository-relative globs in `.wakindexignore` exclude intentional fixtures or generated content.
Ignore rules are a reviewer decision and part of the trusted configuration boundary.

## Failure behavior

- unreadable or malformed candidate agent files are skipped without executing fallback logic;
- an invalid scan path, user profile path, or policy returns exit code `1`;
- an invalid account catalog, duplicate account ID, or unreadable profile boundary returns `1`;
- policy violations return exit code `2`;
- compliant scans and audits return `0`;
- machine formats remain valid on stdout, with diagnostics sent to stderr.

## Extension contract

Runtime access-graph freshness uses RFC3339 timestamps with known timezone offsets. Expiration
compares instants, including equality with `valid_until`, rather than timestamp strings. Once
marked stale, a record stays stale until a new observation replaces it; clock regression cannot
refresh it. Invalid timestamps, unknown offsets, reversed windows, and non-boolean stale flags
are rejected before persistence.

To support a new ecosystem:

1. document the authoritative format and whether its scope is workspace, user, or system;
2. add a scanner returning normalized `Finding` values;
3. use explicit known paths for user/system discovery rather than recursive traversal;
4. add sanitized safe and adversarial fixtures;
5. test determinism, path containment, home redaction, and credential-value safety;
6. extend the taxonomy only when existing permission IDs cannot express the capability;
7. test scoped policy selectors and deny precedence for new metadata;
8. update this document, the policy reference, README, and changelog.

For new identity hints, also prove that model identifiers and auth-context labels are documented,
non-secret, deterministic, and do not expose the profile home.
