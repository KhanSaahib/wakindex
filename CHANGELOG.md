# Changelog

## Description

All notable user-visible changes to wakindex are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and releases follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

- Compare access-evidence freshness using timezone-aware instants, expire at the validity boundary,
  and keep stale evidence stale across clock regressions. Reject invalid freshness timestamps.

### Added

- Collectors for network posture with an observed/inferred reachability split, configured tool
  and MCP transports, and credential references recorded by name only.
- Bounded access collectors for principal and capability authority, process lineage with
  inherited descriptors, and the mount table with propagation mode.
- Access graph records, snapshot normalization, and diff semantics that keep a collector
  failure distinct from revoked access.
- SQLite snapshot store with versioned migrations, transactional writes, and refusal to read a
  store written by a newer build.
- Offline dependency bundle, pinned and hashed dev dependency lock, and an offline build,
  install, and test procedure documented in `docs/offline-build.md`.
- `scripts/verify_offline.sh`, which runs install, tests, and the wheel build inside a network
  namespace with no external route.
- Regression tests rejecting outbound network clients in the runtime.
- Golden contract fixtures for the access graph, policy precedence, and session lifecycle.
- Local-first scanner, policy engine, CLI, SARIF output, browser policy editor, Docker image, and
  GitHub Action.
- Tag-driven GitHub Release workflow with wheel artifacts and SHA-256 checksums.
- Explicit SemVer, changelog, and release process in `RELEASE.md`.
- Two-part WAK / INDEX panel with init guidance.
- Environment audits for known Codex, Claude, Cursor, Gemini, VS Code, and Claude Desktop user
  configuration.
- Native Codex TOML scanning, Claude hook discovery, sandbox write/network grants, auto-approval
  and embedded-credential signals, and privacy-preserving user source labels.
- Versioned, resource-scoped policy rules with stable IDs, metadata selectors, reasons, and deny
  precedence.
- Copyable personal and corporate policy examples.
- Account-aware `identity-1.0` inventory for human, service, and shared accounts, including
  configured models, model providers, provider-account aliases, authentication context, effective
  access, and policy decisions.
- Read-only enterprise identity and access dashboard with posture metrics, attribution coverage,
  identity map, permission matrix, filters, secure same-origin JSON export, and loopback security
  headers.
- Strict enterprise account catalog plus a copyable multi-account template.

### Changed

- Standardized the product name as lowercase `wakindex`.
- Limited the startup panel to `wakindex init` so scan, check, UI, and help remain compact.
- Expanded architecture, contribution, security, and user documentation.
- Added provider and workspace/user scope metadata to normalized findings.
- Preserved the existing manifest, SARIF, policy editor, GitHub Action, and CLI behavior while
  adding separate `inventory` and `dashboard` workflows.
