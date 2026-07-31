#!/usr/bin/env bash
# Build the webhook image, load it into kind, and deploy the webhook with its
# policy, key, attestations, and TLS material.
set -euo pipefail

cd "$(dirname "$0")"

CLUSTER_NAME="${CLUSTER_NAME:-cilock}"
REG_NAME="${REG_NAME:-cilock-registry}"
REG_PORT="${REG_PORT:-5001}"

# 1. webhook image (binary cross-compiled on the host; see Dockerfile)
(cd .. && mkdir -p bin && CGO_ENABLED=0 GOOS=linux GOARCH="$(go env GOHOSTARCH)" go build -o bin/cilock-k8s . \
  && docker build -q -t cilock-k8s:dev .)
kind load docker-image cilock-k8s:dev --name "${CLUSTER_NAME}"

# 2. the registry's address on the kind docker network — the webhook pod
# cannot use localhost:${REG_PORT}, that name only works on the host and the
# nodes' containerd mirror.
REGISTRY_IP="$(docker inspect "${REG_NAME}" -f '{{.NetworkSettings.Networks.kind.IPAddress}}')"
REGISTRY_ADDR="${REGISTRY_IP}:5000"

kubectl create namespace cilock-system --dry-run=client -o yaml | kubectl apply -f -

kubectl -n cilock-system create secret tls cilock-webhook-tls \
  --cert=.tls/tls.crt --key=.tls/tls.key \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n cilock-system create configmap cilock-config \
  --from-file=policy.signed.json=.artifacts/policy.signed.json \
  --from-file=policy-pub.pem=.keys/policy-pub.pem \
  --dry-run=client -o yaml | kubectl apply -f -

kubectl -n cilock-system create configmap cilock-attestations \
  --from-file=.artifacts/attestations \
  --dry-run=client -o yaml | kubectl apply -f -

CA_BUNDLE="$(openssl base64 -A < .tls/ca.crt)"

sed -e "s|{{REGISTRY_ADDR}}|${REGISTRY_ADDR}|g" \
    -e "s|{{REG_PORT}}|${REG_PORT}|g" \
    -e "s|{{CA_BUNDLE}}|${CA_BUNDLE}|g" \
    manifests/webhook.tmpl.yaml | kubectl apply -f -

kubectl -n cilock-system rollout restart deployment cilock-webhook
kubectl -n cilock-system rollout status deployment cilock-webhook --timeout=120s

echo "webhook deployed"
