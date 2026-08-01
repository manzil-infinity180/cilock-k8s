#!/usr/bin/env bash
# Build and push the demo image, attest it with witness, and generate a
# signed witness policy for it. Everything lands in dev/.artifacts.
#
# Unlike cilock (see the cilock-poc/main branch), upstream witness has no
# `policy from-bundles` generator, so this script constructs the policy JSON
# itself from the signing key and the attestation types the run produces.
set -euo pipefail

cd "$(dirname "$0")"

REG_PORT="${REG_PORT:-5001}"
DEMO_IMAGE="localhost:${REG_PORT}/cilock-demo:1"
UNATTESTED_IMAGE="localhost:${REG_PORT}/unattested:1"
WITNESS_VERSION="${WITNESS_VERSION:-v0.12.0}"

command -v jq >/dev/null || { echo "jq is required"; exit 1; }

mkdir -p .bin .keys .artifacts/attestations

# 1. witness CLI (published module — no local checkout needed)
if [ ! -x .bin/witness ]; then
  echo "installing witness ${WITNESS_VERSION}..."
  GOBIN="$(pwd)/.bin" go install "github.com/in-toto/witness@${WITNESS_VERSION}"
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
RUN echo "attested by witness" > /demo.txt
CMD ["sleep", "3600"]
EOF
docker build -q -f .artifacts/Dockerfile.demo -t "${DEMO_IMAGE}" .artifacts
docker push -q "${DEMO_IMAGE}"

rm -f .artifacts/build.att.json .artifacts/demo.tar .artifacts/attestations/*
.bin/witness run \
  --step build \
  --attestations oci \
  --signer-file-key-path .keys/policy-key.pem \
  --outfile .artifacts/build.att.json \
  -- docker save -o .artifacts/demo.tar "${DEMO_IMAGE}"
cp .artifacts/build.att.json .artifacts/attestations/

# 4. an unattested control image for the deny test
docker pull -q busybox:latest >/dev/null
docker tag busybox:latest "${UNATTESTED_IMAGE}"
docker push -q "${UNATTESTED_IMAGE}"

# 5. construct the policy: step "build" must carry these attestations, signed
# by our key. The keyid is taken from the attestation we just signed so it
# always matches witness's own keyid derivation.
KEYID="$(jq -r '.signatures[0].keyid' .artifacts/build.att.json)"
PUB_B64="$(openssl base64 -A < .keys/policy-pub.pem)"
EXPIRES="$(date -u -v+1y +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+1 year' +%Y-%m-%dT%H:%M:%SZ)"

jq -n --arg keyid "${KEYID}" --arg key "${PUB_B64}" --arg expires "${EXPIRES}" '{
  expires: $expires,
  steps: {
    build: {
      name: "build",
      attestations: [
        {type: "https://witness.dev/attestations/material/v0.1"},
        {type: "https://witness.dev/attestations/command-run/v0.1"},
        {type: "https://witness.dev/attestations/product/v0.1"},
        {type: "https://witness.dev/attestations/oci/v0.1"}
      ],
      functionaries: [
        {type: "publickey", publickeyid: $keyid}
      ]
    }
  },
  publickeys: {
    ($keyid): {keyid: $keyid, key: $key}
  }
}' > .artifacts/policy.json

.bin/witness sign \
  --signer-file-key-path .keys/policy-key.pem \
  --datatype "https://witness.testifysec.com/policy/v0.1" \
  --infile .artifacts/policy.json \
  --outfile .artifacts/policy.signed.json

echo "demo image ${DEMO_IMAGE} attested; signed policy in dev/.artifacts/policy.signed.json"
