# Contributing to wakindex

## Description

This guide defines the development, security, testing, documentation, and review expectations for
wakindex contributions.

## Set up

```bash
python -m venv .venv
# Activate the environment for your shell.
python -m pip install -e ".[dev]"
```

## Make a change

1. Start from a focused issue or clearly stated permission-format problem.
2. Add a sanitized realistic fixture and failing test before behavior changes.
3. Keep scanners static: never execute input, resolve secret values, or require network access.
4. Preserve deterministic manifests and stable exit codes.
5. User-profile discovery must use explicit known paths, skip symlinks, redact the home prefix,
   and never recursively crawl the profile.
6. Update README, architecture, policy, changelog, and release documentation when their contracts
   change.

Every source or configuration file must begin with a short description comment where its format
supports comments.

## Verify

Required:

```bash
python -m pytest
python -m ruff check .
git diff --check
```

For offline guarantees, dependency, or build-script changes:

```bash
python scripts/offline_bundle.py fetch
python -m venv /tmp/wakindex-offline-venv
scripts/verify_offline.sh /tmp/wakindex-offline-venv
```

See [docs/offline-build.md](docs/offline-build.md) for the dependency inventory and the full
procedure.

For packaging, Docker, entrypoint, action, or release changes:

```bash
python -m pip wheel . --no-deps --wheel-dir dist
docker build --target test -t wakindex-test .
docker run --rm wakindex-test
```

## Pull requests

Keep commits focused and explain user impact, security implications, compatibility, and validation.
Do not include credentials or copied production configuration in fixtures. New permission IDs must
be documented in `docs/architecture.md`. New policy selectors must be documented in
`docs/policy.md` and tested for deny precedence.

Maintainers follow [RELEASE.md](RELEASE.md) for version changes and tags. Contributors should add
user-visible changes to the `Unreleased` section of `CHANGELOG.md`.
