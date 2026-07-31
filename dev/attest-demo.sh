#!/usr/bin/env bash
# Build and push the demo image, attest it with cilock, and generate a signed
# witness policy from the attestation. Everything lands in dev/.artifacts.
set -euo pipefail

cd "$(dirname "$0")"

REG_PORT="${REG_PORT:-5001}"
DEMO_IMAGE="localhost:${REG_PORT}/cilock-demo:1"
UNATTESTED_IMAGE="localhost:${REG_PORT}/unattested:1"
CILOCK_DIR="${CILOCK_DIR:-$(pwd)/../../judge/subtrees/rookery/cilock}"

mkdir -p .bin .keys .artifacts/attestations

# 1. cilock binary
if [ ! -x .bin/cilock ]; then
  echo "building cilock from ${CILOCK_DIR}..."
  (cd "${CILOCK_DIR}" && go build -o "${OLDPWD}/.bin/cilock" ./cmd/cilock)
fi

# 2. policy signing keypair
if [ ! -f .keys/policy-key.pem ]; then
  openssl ecparam -genkey -name prime256v1 -noout -out .keys/policy-key.pem
  openssl ec -in .keys/policy-key.pem -pubout -out .keys/policy-pub.pem 2>/dev/null
  echo "generated policy keypair in dev/.keys"
fi

# 3. demo image: build, push, and attest the `docker save` tar with the oci
# attestor. The attestation's `imageid` subject (the image config digest) is
# what the admission webhook later matches after resolving the pod's image
# from the registry.
cat > .artifacts/Dockerfile.demo <<'EOF'
FROM busybox
RUN echo "attested by cilock" > /demo.txt
CMD ["sleep", "3600"]
EOF
docker build -q -f .artifacts/Dockerfile.demo -t "${DEMO_IMAGE}" .artifacts
docker push -q "${DEMO_IMAGE}"

# cilock writes sidecar files (e.g. *.detection.json) next to the outfile, so
# attest into .artifacts and copy only the DSSE envelope into attestations/.
rm -f .artifacts/build.att.json* .artifacts/demo.tar .artifacts/attestations/*
.bin/cilock run \
  --step build \
  --workload manual \
  --attestations oci \
  --signer-file-key-path .keys/policy-key.pem \
  --outfile .artifacts/build.att.json \
  --platform-url "" \
  -- docker save -o .artifacts/demo.tar "${DEMO_IMAGE}"
cp .artifacts/build.att.json .artifacts/attestations/

# 4. an unattested control image for the deny test
docker pull -q busybox:latest >/dev/null
docker tag busybox:latest "${UNATTESTED_IMAGE}"
docker push -q "${UNATTESTED_IMAGE}"

# 5. signed policy generated from the attestation bundle
.bin/cilock policy from-bundles -k .keys/policy-pub.pem \
  .artifacts/attestations/build.att.json > .artifacts/policy.json
.bin/cilock sign -k .keys/policy-key.pem \
  -f .artifacts/policy.json -o .artifacts/policy.signed.json --platform-url ""

echo "demo image ${DEMO_IMAGE} attested; signed policy in dev/.artifacts/policy.signed.json"
