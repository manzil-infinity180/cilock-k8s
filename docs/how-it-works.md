# How cilock-k8s works, end to end

This document walks through every stage of the PoC — what each script in
`dev/` creates, why it exists, and what happens at admission time.

## The big picture

Supply-chain security question this PoC answers: **"only run container images
that we can prove were built by our pipeline."**

The proof is a signed **attestation** (evidence recorded at build time), and
the rule is a signed **policy** (what evidence is required). The admission
webhook is the enforcement point that connects the two.

```
 BUILD TIME (dev/attest-demo.sh)                 ADMISSION TIME (webhook)
 ───────────────────────────────                 ────────────────────────
                                                 kubectl run …
 docker build ──► demo image                          │
      │                                               ▼
      ▼                                    ┌─ API server ────────────┐
 docker push ──► localhost:5001            │ namespace labeled       │
      │                                    │ cilock-policy=enforce?  │
      ▼                                    └──────────┬──────────────┘
 cilock run --step build -a oci                       │ AdmissionReview (pod spec)
   wraps: docker save (image tar)                     ▼
   records: imageid, manifestdigest,       ┌─ cilock-k8s webhook ────────────────┐
            layer digests, materials…      │ 1. image ref ──► registry lookup    │
      │                                    │    ──► manifest digest + image ID   │
      ▼                                    │ 2. find attestations whose SUBJECTS │
 build.att.json                            │    contain those digests            │
 (DSSE envelope, signed)                   │ 3. workflow.Verify:                 │
      │                                    │    • policy signature valid?        │
      ▼                                    │    • attestation signature valid?   │
 cilock policy from-bundles                │    • signer is a trusted            │
   + cilock sign                           │      functionary for step "build"?  │
      │                                    │    • required attestors present?    │
      ▼                                    └──────┬──────────────────────────────┘
 policy.signed.json ───────────────────────────►  │
 policy-pub.pem (trust anchor) ────────────────►  ▼
                                             allow / deny
```

Three artifacts cross from build time to admission time:

| artifact | what it is | mounted at |
|---|---|---|
| `build.att.json` | signed DSSE **collection envelope** — the evidence | `/etc/cilock/attestations/` |
| `policy.signed.json` | signed witness policy — the rule | `/etc/cilock/config/` |
| `policy-pub.pem` | public key the webhook trusts to have signed the policy | `/etc/cilock/config/` |

## Stage 1 — `dev/kind-up.sh`: a cluster with a real registry

Creates two things:

1. A **registry container** (`cilock-registry`, `registry:2` image) published
   on `localhost:5001` on your host.
2. A **kind cluster** (`cilock`) whose containerd is configured with a mirror
   so that image refs like `localhost:5001/foo` are fetched from the registry
   container over the docker network.

**Why a registry at all?** The webhook verifies the image a pod *references*,
which means it must resolve `localhost:5001/cilock-demo:1` to content digests
by asking a registry. `kind load docker-image` (which copies an image
straight onto the node) would leave nothing for the webhook to query. A real
push/pull through a registry is also what production looks like.

**Why the containerd mirror?** `localhost:5001` only means something on your
host. Inside a kind node, "localhost" is the node itself — so nodes are told
"when asked for `localhost:5001`, fetch from `http://cilock-registry:5000`
instead" (that's the `hosts.toml` the script writes into each node).

## Stage 2 — `dev/gen-certs.sh`: TLS for the webhook

The Kubernetes API server **only calls admission webhooks over HTTPS**, and it
must be told which CA to trust. The script creates:

- `ca.crt` / `ca.key` — a throwaway CA. `ca.crt` gets base64-embedded as the
  `caBundle` in the ValidatingWebhookConfiguration ("API server, trust
  certificates signed by this").
- `tls.crt` / `tls.key` — the serving certificate, with subject alternative
  name `cilock-webhook.cilock-system.svc` — exactly the DNS name the API
  server uses to reach the webhook Service. Wrong SAN = TLS handshake
  failure = (with `failurePolicy: Fail`) every pod creation in enforced
  namespaces rejected.

These certs are about **transport security between the API server and the
webhook** — completely separate from the attestation-signing keys in stage 3.

## Stage 3 — `dev/attest-demo.sh`: evidence and policy

This is the "build pipeline" of the demo. Step by step:

1. **Builds `cilock`** from your local rookery checkout (`CILOCK_DIR`) into
   `dev/.bin/cilock`.
2. **Generates a signing keypair** (`dev/.keys/policy-key.pem` /
   `policy-pub.pem`). For simplicity one key plays both roles: the
   *functionary* (signs attestations) and the *policy signer* (signs the
   policy). In production these would be different identities — e.g. keyless
   Fulcio certificates per CI run for attestations, and an offline org key
   for the policy.
3. **Builds and pushes the demo image** `localhost:5001/cilock-demo:1`.
4. **Attests the build**:

   ```
   cilock run --step build -a oci --signer-file-key-path … \
     -- docker save -o demo.tar localhost:5001/cilock-demo:1
   ```

   `cilock run` executes the wrapped command and records attestations around
   it, then signs everything into one DSSE **collection envelope**
   (`build.att.json`). The attestors that run:

   - `material` — inputs present before the command,
   - `product` — files the command produced (`demo.tar`),
   - `oci` — parses the produced tar and records the image's **image ID
     (config digest)**, manifest digest, layer digests, and tag as
     **subjects** of the attestation.

   The subjects are the whole trick: they are the digests this evidence is
   *about*, and they're what the webhook searches by later.

   > Why attest a `docker save` tar instead of the pushed image? The tar's
   > manifest digest differs from the registry's, but the **image ID (config
   > digest) is identical in both**. That makes the image ID the reliable
   > join key between "what the build machine attested" and "what the node
   > will run". (This detail is what the original 2022 PoC struggled with.)

5. **Pushes an unattested control image** (`localhost:5001/unattested:1`,
   plain busybox) so you can demo the deny path.
6. **Generates the policy**: `cilock policy from-bundles` inspects the
   attestation bundle and emits a starter policy that says roughly *"a step
   named `build` must exist, containing material/product/oci attestations,
   signed by a functionary with this public key"*. Then `cilock sign` wraps
   the policy itself in a signed DSSE envelope (`policy.signed.json`) — the
   policy is trusted content too; an unsigned policy could be swapped out.

## Stage 4 — `dev/deploy.sh`: the enforcement point

1. **Builds the webhook binary** on your host (`CGO_ENABLED=0 GOOS=linux`)
   and a `cilock-k8s:dev` image from it, then `kind load`s it onto the node.
   (Host-built because `go.mod` reaches into the local rookery checkout via
   `replace` directives that a Docker build context can't see.)
2. **Looks up the registry's IP on the docker network** and passes
   `--registry-alias localhost:5001=<ip>:5000` to the webhook. Same problem
   the containerd mirror solves for nodes, solved for the webhook pod: it
   receives image refs saying `localhost:5001` but must dial the registry
   container instead. `--insecure-registry` marks it as plain-HTTP (dev
   registry has no TLS).
3. **Creates the runtime objects**:
   - Secret `cilock-webhook-tls` — the serving cert/key from stage 2,
   - ConfigMap `cilock-config` — `policy.signed.json` + `policy-pub.pem`,
   - ConfigMap `cilock-attestations` — the attestation envelope(s),
   - Deployment + Service `cilock-webhook` in namespace `cilock-system`.
4. **Registers the `ValidatingWebhookConfiguration`** — this is what makes
   the API server call us. The important fields:

   | field | value | meaning |
   |---|---|---|
   | `rules` | `CREATE` `pods` | only pod creation is intercepted |
   | `namespaceSelector` | `cilock-policy: enforce` | only namespaces with this label are enforced — this is also what keeps the webhook from blocking `kube-system` or itself |
   | `failurePolicy` | `Fail` | if the webhook is down, pod creation in enforced namespaces is rejected (fail-closed) |
   | `clientConfig` | service + `caBundle` | where to call, and which CA to trust |

## Stage 5 — admission time

When you `kubectl run` a pod in an enforced namespace:

1. The API server sends the webhook an `AdmissionReview` containing the full
   pod spec (the pod does not exist yet — nothing has been scheduled or
   pulled).
2. The webhook walks every `initContainer` and `container` image ref,
   resolves each against the registry (applying aliases), and gets the
   manifest digest + image ID.
3. `workflow.Verify` runs the full witness verification: policy signature →
   candidate attestation search **by subject digest** → envelope signature →
   functionary/key check → required-attestor check per policy step.
4. Allow or deny. On deny, the error you see from `kubectl` *is* the
   verification failure, and the pod is never created.

### Reading the webhook logs

From a real run:

```
[verified-source] verifying 1 candidate envelope(s) for collection "build"
[dsse-verify] roots=0 intermediates=0 verifiers=1 timestampVerifiers=0 sigs=1
[verified-source] envelope … signature OK (verifier kid=c5c613cf4b59)
PASS pod=cilock-demo/attested … imageid=sha256:b76c… steps=[build]
```

- `1 candidate envelope(s)` — the subject-digest search found an attestation
  whose subjects contain this image's digest. Signature is then verified
  (`signature OK`, with the key ID).
- For the unattested image you instead see
  `verifying 0 candidate envelope(s) for collection "build"` — **no evidence
  even mentions this image's digests**, so the policy's `build` step can't be
  satisfied → `DENY`. That "0 candidates" line is the search coming up empty,
  which is exactly the point.

## What's deliberately simplified (PoC)

- Evidence is static ConfigMap mounts. Real deployments would query
  [Archivista](https://github.com/in-toto/archivista) (any
  `source.Sourcer` can be plugged in).
- One key signs everything; no keyless/Fulcio, no timestamps, no cert chains.
- Only `CREATE pod` is checked — enough, since every higher-level workload
  eventually creates pods.
