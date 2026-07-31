#!/usr/bin/env bash
# End-to-end admission test: a pod running the attested image must be
# admitted; a pod running an unattested image must be denied.
set -euo pipefail

cd "$(dirname "$0")"

REG_PORT="${REG_PORT:-5001}"
DEMO_IMAGE="localhost:${REG_PORT}/cilock-demo:1"
UNATTESTED_IMAGE="localhost:${REG_PORT}/unattested:1"
NS="cilock-demo"

kubectl create namespace "${NS}" --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace "${NS}" cilock-policy=enforce --overwrite

kubectl -n "${NS}" delete pod attested --ignore-not-found >/dev/null

echo "--- admitting attested image ${DEMO_IMAGE} (should PASS)"
if ! kubectl -n "${NS}" run attested --image="${DEMO_IMAGE}" --restart=Never; then
  echo "FAIL: attested image was denied"
  exit 1
fi
kubectl -n "${NS}" wait --for=condition=Ready pod/attested --timeout=60s

echo "--- admitting unattested image ${UNATTESTED_IMAGE} (should be DENIED)"
if kubectl -n "${NS}" run unattested --image="${UNATTESTED_IMAGE}" --restart=Never 2>deny.err; then
  echo "FAIL: unattested image was admitted"
  exit 1
fi

if ! grep -qi "policy" deny.err; then
  echo "FAIL: denial did not mention the policy:"
  cat deny.err
  exit 1
fi

echo "--- denial message:"
cat deny.err
rm -f deny.err

echo
echo "E2E PASSED: attested image admitted, unattested image denied"
