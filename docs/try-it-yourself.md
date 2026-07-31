# Try it yourself

A hands-on walkthrough with expected output at every step, plus experiments
to convince yourself the verification is real. Background for each step is in
[how-it-works.md](how-it-works.md).

## Prerequisites

- Go ≥ 1.26, Docker (running), kind, kubectl, openssl
- A local [rookery](https://github.com/aflock-ai/rookery) checkout; set
  `CILOCK_DIR` if it's not at the default path in `dev/attest-demo.sh`,
  and fix the `replace` paths in `go.mod` to match.

## The one-command version

```bash
make e2e
```

Expect the last line:

```
E2E PASSED: attested image admitted, unattested image denied
```

Everything below does the same thing manually so you can see each part.

## Step 1 — cluster + registry

```bash
./dev/kind-up.sh
```

```
kind cluster 'cilock' ready; registry 'cilock-registry' on localhost:5001
```

Sanity check the registry: `curl -s localhost:5001/v2/_catalog` → `{"repositories":[]}`.

## Step 2 — webhook TLS

```bash
./dev/gen-certs.sh          # → dev/.tls/{ca.crt,tls.crt,tls.key}
```

## Step 3 — build, attest, make the policy

```bash
./dev/attest-demo.sh
```

In the `cilock run` summary, find the subjects line and note the
`oci/v0.1/imageid:` value — that digest is the link the webhook will check:

```
subjects (8): …, oci/v0.1/imageid:b76c63fdc4d9…, oci/v0.1/manifestdigest:…, …
```

Poke at the artifacts:

```bash
# the DSSE envelope: payload + signature
jq 'keys' dev/.artifacts/build.att.json
# → ["payload","payloadType","signatures"]

# the attestation inside: a collection with material/product/oci
jq -r .payload dev/.artifacts/build.att.json | base64 -d | jq '.predicate.attestations[].type'

# the subjects the webhook searches by
jq -r .payload dev/.artifacts/build.att.json | base64 -d | jq '.subject[].name'

# the (unsigned) policy: which step requires what, signed by whom
jq '.steps' dev/.artifacts/policy.json
```

## Step 4 — deploy the webhook

```bash
./dev/deploy.sh
```

```
deployment "cilock-webhook" successfully rolled out
webhook deployed
```

## Step 5 — watch it decide

Terminal 1 — follow the logs:

```bash
kubectl -n cilock-system logs deploy/cilock-webhook -f
```

Terminal 2 — an enforced namespace:

```bash
kubectl create ns cilock-demo --dry-run=client -o yaml | kubectl apply -f -
kubectl label ns cilock-demo cilock-policy=enforce --overwrite
```

**Allow case** — the attested image:

```bash
kubectl -n cilock-demo run attested --image=localhost:5001/cilock-demo:1 --restart=Never
# → pod/attested created
```

Log shows the subject search finding the envelope, the signature check, and
the verdict:

```
[verified-source] verifying 1 candidate envelope(s) for collection "build"
[verified-source] envelope … signature OK (verifier kid=…)
PASS pod=cilock-demo/attested … imageid=sha256:b76c… steps=[build]
```

**Deny case** — plain busybox:

```bash
kubectl -n cilock-demo run unattested --image=localhost:5001/unattested:1 --restart=Never
```

```
Error from server: admission webhook "cilock-webhook.cilock-system.svc" denied the request:
witness policy verification failed: … failed policy verification
```

In the logs, the tell-tale line is `verifying 0 candidate envelope(s)` — no
attestation's subjects contain busybox's digests, so there is no evidence to
verify and the policy step can't be satisfied.

## Experiments

**1. Tampered image is denied.** Rebuild with any change, push, admit — the
image ID changed, the old attestation no longer applies:

```bash
printf 'FROM busybox\nRUN echo tampered > /demo.txt\nCMD ["sleep","3600"]\n' | \
  docker build -t localhost:5001/cilock-demo:1 -f - .
docker push localhost:5001/cilock-demo:1
kubectl -n cilock-demo run tampered --image=localhost:5001/cilock-demo:1 --restart=Never
# → denied
```

(Restore with `./dev/attest-demo.sh && ./dev/deploy.sh` — re-attests the new
image and reloads the ConfigMaps.)

**2. Unlabeled namespaces are untouched.** The webhook is opt-in per
namespace, so this works and never even hits the webhook:

```bash
kubectl run free --image=busybox --restart=Never -- sleep 60
```

**3. Verify with no cluster at all.** The same engine runs as a CLI:

```bash
go build -o cilock-k8s .
./cilock-k8s verify \
  --policy dev/.artifacts/policy.signed.json \
  --policy-key dev/.keys/policy-pub.pem \
  --attestation-dir dev/.artifacts/attestations \
  --insecure-registry localhost:5001 \
  localhost:5001/cilock-demo:1
# → ALLOWED: … steps=[build]
```

**4. Wrong trust anchor is rejected.** Hand the webhook a different public
key and even the attested image fails (policy signature can't be verified):

```bash
openssl ecparam -genkey -name prime256v1 -noout | openssl ec -pubout > /tmp/wrong-pub.pem 2>/dev/null
./cilock-k8s verify \
  --policy dev/.artifacts/policy.signed.json \
  --policy-key /tmp/wrong-pub.pem \
  --attestation-dir dev/.artifacts/attestations \
  --insecure-registry localhost:5001 \
  localhost:5001/cilock-demo:1
# → DENIED
```

## Troubleshooting

| symptom | cause / fix |
|---|---|
| `pods "attested" already exists` | leftover from a previous run: `kubectl -n cilock-demo delete pod attested` |
| every pod in the namespace rejected with a TLS/connect error | webhook down or cert mismatch (`failurePolicy: Fail` is fail-closed) — check `kubectl -n cilock-system get pods` and redeploy |
| webhook denies with a registry connection error | registry container IP changed (recreated registry) — re-run `./dev/deploy.sh` to re-template `--registry-alias` |
| `no attestation envelopes (*.json) found` on startup | attestations ConfigMap empty — re-run `./dev/attest-demo.sh && ./dev/deploy.sh` |

## Teardown

```bash
make dev-down
```
