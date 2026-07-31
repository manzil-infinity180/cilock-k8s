#!/usr/bin/env bash
# Tear down the kind cluster and the local registry.
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-cilock}"
REG_NAME="${REG_NAME:-cilock-registry}"

kind delete cluster --name "${CLUSTER_NAME}" || true
docker rm -f "${REG_NAME}" >/dev/null 2>&1 || true
echo "torn down"
