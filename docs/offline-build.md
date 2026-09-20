# Offline build and test

## Description

This document defines the dependency inventory and the procedure for building, installing, and
testing wakindex on a host with no outbound network access.

## Dependency inventory

### Runtime

None. wakindex runs on the Python standard library alone. Python 3.11 or newer is required.

The runtime opens no outbound connection. `tests/test_offline_guarantee.py` enforces this: it
rejects any import of an HTTP or socket client in `src/wakindex`, and it requires the local UI and
dashboard to bind loopback explicitly rather than all interfaces. Those two servers are inbound
listeners on `127.0.0.1`; they are not remote calls.

### Development

Pinned with hashes in `requirements-dev.txt`, generated from `requirements-dev.in`.

| Package | Purpose |
| --- | --- |
| `pytest` | Test runner |
| `ruff` | Lint and format checks |
| `iniconfig`, `packaging`, `pluggy`, `pygments` | pytest dependencies |
| `colorama` | pytest dependency, Windows only |

### Build

`hatchling` is the build backend declared in `pyproject.toml`, and `editables` is the package
hatchling imports when producing an editable wheel. Both are bundled, because pip cannot fetch a
build backend on a disconnected host.

To print the inventory from the repository:

```bash
python scripts/offline_bundle.py inventory
```

## Preparing the bundle

Run once on a connected host. This is the only step that needs network access.

```bash
python scripts/offline_bundle.py fetch
```

Wheels land in `vendor/wheels`, which is not tracked by git. Dependency wheels are verified against
the hashes in `requirements-dev.txt`; `pip download --require-hashes` fails rather than accepting a
substituted artifact. Copy the whole `vendor/wheels` directory to the disconnected host along with
the repository.

## Installing and testing offline

```bash
python -m venv .venv
python scripts/offline_bundle.py install --python .venv/bin/python
python scripts/offline_bundle.py verify --python .venv/bin/python
```

`install` passes `--no-index`, so pip never contacts an index. `verify` runs pytest and ruff.

## Verifying the offline claim

`scripts/verify_offline.sh` proves the claim rather than asserting it. It re-runs install, test,
and wheel build inside a network namespace that has no route off the host:

```bash
python -m venv /tmp/wakindex-offline-venv
scripts/verify_offline.sh /tmp/wakindex-offline-venv
```

The script needs unprivileged user namespaces, and no root or sudo. It brings loopback up inside
the namespace, because a disconnected host still has loopback and some tests use it; the property
under test is that no external route exists. It then attempts an outbound connection and aborts if
that connection succeeds, so a misconfigured namespace cannot produce a false pass.
