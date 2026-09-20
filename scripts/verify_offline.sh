#!/usr/bin/env bash
# Description: Install, test, and build wakindex inside a network namespace with no external route.
#
# Models a disconnected host: loopback stays up, every other route is gone. Requires a prepared
# bundle (scripts/offline_bundle.py fetch) and unprivileged user namespaces. No root, no sudo.
#
# Usage: scripts/verify_offline.sh [venv-path]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${1:-/tmp/wakindex-offline-venv}"

if [ ! -d "${REPO_ROOT}/vendor/wheels" ]; then
  echo "no bundle at vendor/wheels; run 'python scripts/offline_bundle.py fetch' first" >&2
  exit 1
fi

exec unshare --user --map-root-user --net --fork bash -euo pipefail -c '
REPO_ROOT="'"${REPO_ROOT}"'"
VENV="'"${VENV}"'"
cd "${REPO_ROOT}"

# A fresh network namespace starts with loopback down. A disconnected host still has loopback,
# so bring it up: the property under test is "no external route", not "no networking at all".
ip link set lo up

echo "== egress check =="
python3 - <<PY
import socket
try:
    socket.create_connection(("1.1.1.1", 443), timeout=3)
except OSError as err:
    print(f"external egress blocked: {type(err).__name__}: {err}")
else:
    raise SystemExit("external network reachable; offline verification is invalid")
PY

echo "== install from bundle =="
"${VENV}/bin/python" scripts/offline_bundle.py install --python "${VENV}/bin/python"

echo "== test and lint =="
"${VENV}/bin/python" scripts/offline_bundle.py verify --python "${VENV}/bin/python"

echo "== build wheel =="
"${VENV}/bin/python" -m pip wheel . --no-deps --no-build-isolation --wheel-dir "$(mktemp -d)"

echo "== offline verification passed =="
'
