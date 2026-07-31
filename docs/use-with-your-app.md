# Using cilock-k8s with your own application

Step-by-step guide to protecting **your** application with the webhook:
attest your image, create and sign your policy, deploy the webhook with your
trust material, and enforce it on your namespaces.

Throughout, replace:

- `REG` — your registry (e.g. `ghcr.io/you`, `localhost:5001` for the kind
  dev registry)
- `myapp` / `1.0.0` — your image name / tag

## 0. What you need

- `cilock` built from your rookery checkout:
  `cd <rookery>/cilock && go build -o ~/bin/cilock ./cmd/cilock`
- A registry that both your cluster nodes **and the webhook pod** can reach
  (the webhook resolves image digests from it at admission time).
- A cluster with the webhook deployable (see step 5 — the PoC scripts target
  kind, but the manifests work anywhere).

## 1. Create your signing keys

Two logical roles — for a first run one key can play both (that's what the
demo does), but separating them is the real-world shape:

```bash
# functionary key: signs attestations (your CI would hold this)
openssl ecparam -genkey -name prime256v1 -noout -out functionary-key.pem
openssl ec -in functionary-key.pem -pubout -out functionary-pub.pem

# policy key: signs the policy itself (an org/security-team key)
openssl ecparam -genkey -name prime256v1 -noout -out policy-key.pem
openssl ec -in policy-key.pem -pubout -out policy-pub.pem
```

The webhook is configured with **only `policy-pub.pem`** — it's the single
trust anchor. Trust in the functionary key comes from *inside* the signed
policy (its public key is embedded there in step 3).

## 2. Attest your image build

Build and push as usual, then attest a `docker save` of the exact image you
pushed, wrapping it with `cilock run`:

```bash
docker build -t REG/myapp:1.0.0 .
docker push REG/myapp:1.0.0

cilock run \
  --step build \
  --workload manual \
  --attestations oci \
  --signer-file-key-path functionary-key.pem \
  --outfile myapp-build.att.json \
  --platform-url "" \
  -- docker save -o myapp.tar REG/myapp:1.0.0
```

What this records: `material` (inputs), `product` (`myapp.tar`), and `oci` —
which parses the tar and emits the **image ID (`imageid`) as a subject**.
That subject is what the webhook matches after resolving `REG/myapp:1.0.0`
from the registry, and it's identical between the tar and the registry copy.

Worth knowing:

- Add more evidence with more attestors, e.g.
  `--attestations oci,git,environment` — `git` binds the commit, and the
  generated policy will then *require* those attestations too.
- In CI, run this as the build job itself (e.g. wrap the whole
  `docker build … && docker push … && docker save …` in one
  `cilock run -- sh -c '…'`) so the attestation covers the real pipeline
  step. `cilock plan -- <cmd>` previews which attestors would fire.
- `cilock run` writes a `myapp-build.att.json.detection.json` sidecar — it is
  **not** a DSSE envelope; don't give it to the webhook.

## 3. Create and sign your policy

Generate a starter policy *from* the attestation you just made — it encodes
"a `build` step must exist with these attestation types, signed by this
functionary":

```bash
cilock policy from-bundles -k functionary-pub.pem myapp-build.att.json > policy.json
```

Now **review and edit `policy.json`** — it's plain JSON and it is *your*
rule set:

- `expires` — from-bundles sets a default; set it to a date you actually
  intend to rotate the policy by.
- `steps.build.attestations[]` — the evidence required per step. Add or
  remove attestation types to match what you attest in step 2.
- `steps.build.functionaries[]` / `publickeys` — who may sign build
  attestations. Add each CI signer's public key here.
- Optionally attach [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/)
  modules to an attestation entry to constrain its *contents* (e.g. "the git
  attestation's branch must be `main`") — see the witness policy schema
  (`cilock policy validate --help`, and the witness docs) for the
  `rego` field format.

Validate and sign it with the **policy** key:

```bash
cilock policy validate -p policy.json
cilock sign -k policy-key.pem -f policy.json -o policy.signed.json --platform-url ""
```

Multiple images/pipelines? Either one policy whose steps cover them all, or
one policy per webhook deployment — the PoC webhook loads a single policy.
Attest each image separately and give the webhook *all* the envelopes.

## 4. Give the webhook your trust material

The webhook reads three mounted paths (see `dev/manifests/webhook.tmpl.yaml`):

```bash
kubectl create ns cilock-system

# TLS for the API server → webhook connection (dev/gen-certs.sh does this
# for kind; in a real cluster use cert-manager or your PKI — the cert's SAN
# must be cilock-webhook.cilock-system.svc)
kubectl -n cilock-system create secret tls cilock-webhook-tls \
  --cert=tls.crt --key=tls.key

# your policy + trust anchor
kubectl -n cilock-system create configmap cilock-config \
  --from-file=policy.signed.json --from-file=policy-pub.pem=policy-pub.pem

# your attestation envelopes (repeat --from-file per envelope)
kubectl -n cilock-system create configmap cilock-attestations \
  --from-file=myapp-build.att.json
```

## 5. Deploy the webhook

On kind, `./dev/deploy.sh` does all of this. Elsewhere: build/push the
webhook image (`Dockerfile` expects the binary at `bin/cilock-k8s`,
cross-compile with `CGO_ENABLED=0 GOOS=linux go build -o bin/cilock-k8s .`),
then apply `dev/manifests/webhook.tmpl.yaml` after filling in:

- the image name,
- `{{CA_BUNDLE}}` — base64 of the CA that signed the serving cert,
- the `--registry-alias`/`--insecure-registry` args — **delete them** if your
  registry is a normal HTTPS registry reachable under its real name; they
  exist only for dev registries (private-registry auth uses the standard
  keychain, so mounting a docker config for pull credentials is the
  extension point if you need it).

## 6. Enforce and roll out

```bash
kubectl label namespace myapp-prod cilock-policy=enforce
kubectl -n myapp-prod create deployment myapp --image=REG/myapp:1.0.0
```

Pods from that deployment are now admitted only if `REG/myapp:1.0.0` resolves
to digests covered by a valid, policy-satisfying attestation. Check
`kubectl -n cilock-system logs deploy/cilock-webhook` for the PASS/DENY lines.

Before enforcing a busy namespace, dry-run the exact check locally:

```bash
cilock-k8s verify \
  --policy policy.signed.json --policy-key policy-pub.pem \
  --attestation-dir ./attestations \
  REG/myapp:1.0.0
```

## 7. Shipping a new version

Every new image needs new evidence — that's the security model, not a
limitation:

1. build + push `REG/myapp:1.0.1`
2. `cilock run … -- docker save …` (step 2) → new envelope
3. add the envelope to the `cilock-attestations` ConfigMap and restart the
   webhook (`kubectl -n cilock-system rollout restart deploy/cilock-webhook`)
4. deploy the new image

The policy usually does **not** change per release — only when you rotate
keys, change required evidence, or hit `expires`. (The redeploy-ConfigMap
loop is the PoC's static-store trade-off; an Archivista-backed
`source.Sourcer` would make step 3 automatic.)

## Quick reference: what trusts what

```
policy-pub.pem  ──trusts──►  policy.signed.json  ──trusts──►  functionary keys
 (webhook flag)               (signed rule set)                (inside policy)
                                     │                               │
                                     ▼                               ▼
                              required steps &        attestation envelopes must be
                              attestation types       signed by these + contain the
                                                      pod image's digest as subject
```
