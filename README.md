# cilock-k8s

**Proof-of-concept Kubernetes validating admission webhook that only admits
pods whose container images have verifiable [witness](https://witness.dev)
/ [cilock](https://github.com/aflock-ai/rookery) attestations.**

> **Two variants, same webhook:** this branch (`main`) verifies with the
> [cilock / rookery](https://github.com/aflock-ai/rookery) attestation
> library (more attestors, `policy from-bundles` generator; needs a local
> rookery checkout). The
> [`witness-poc` branch](https://github.com/manzil-infinity180/cilock-k8s/tree/witness-poc)
> verifies with upstream [in-toto go-witness](https://github.com/in-toto/go-witness)
> + the [witness](https://github.com/in-toto/witness) CLI — fully published
> modules, no local checkouts or `replace` directives. Pick the ecosystem
> you use.

When a pod is created in an enforced namespace, the webhook:

1. resolves every container image reference against its registry to the
   image's **manifest digest** and **image ID** (config digest),
2. searches the configured attestation store for signed DSSE collection
   envelopes whose subjects match those digests (the `oci` attestor records
   the image ID as its `imageid` subject at build time),
3. verifies the evidence against a **signed witness policy** using the rookery
   `attestation` library (`workflow.Verify` — the same engine behind
   `cilock verify`),
4. admits the pod only if the policy passes; otherwise the API server returns
   the verification failure to the user:

```
Error from server: admission webhook "cilock-webhook.cilock-system.svc" denied the request:
witness policy verification failed: container "unattested" image "localhost:5001/unattested:1":
image localhost:5001/unattested:1 (manifest=sha256:8f2f... imageid=sha256:e0e8...)
failed policy verification: policy verification failed
```

## How it fits together

```
 build time                                admission time
 ──────────                                ──────────────
 docker build ─┐
               ├─ cilock run -a oci ──► build.att.json (DSSE, signed)
 docker push ──┘        │
                        ▼
        cilock policy from-bundles ──► policy.signed.json
                        │                       │
                        ▼                       ▼
              ┌───────────────────────────────────────┐
 pod create ─►│ cilock-k8s webhook                    │──► allow / deny
              │  image ──► digests ──► workflow.Verify│
              └───────────────────────────────────────┘
```

The PoC runs fully offline: attestations and the policy are mounted into the
webhook pod from ConfigMaps. Swapping the file-based store for Archivista (or
any other `source.Sourcer`) is the natural next step.

## Documentation

📖 **Docs site: [manzil-infinity180.github.io/cilock-k8s](https://manzil-infinity180.github.io/cilock-k8s/)**

| doc | read it when you want to |
|---|---|
| [docs/how-it-works.md](docs/how-it-works.md) | understand every stage — what each `dev/` script creates and why, and how admission-time verification works |
| [docs/try-it-yourself.md](docs/try-it-yourself.md) | run the demo hands-on, with expected output, experiments (tamper / wrong key / no label), and troubleshooting |
| [docs/use-with-your-app.md](docs/use-with-your-app.md) | protect **your own application**: attest your image, create and sign your policy, deploy and enforce |

## Requirements

- Go ≥ 1.26, Docker, kind, kubectl, openssl
- A local checkout of the [rookery](https://github.com/aflock-ai/rookery)
  monorepo (cilock and its `attestation` library). The module is consumed via
  `replace` directives in `go.mod` — adjust those paths (and `CILOCK_DIR` for
  the dev scripts) to your checkout location.

  > **Why a local checkout instead of published modules?** The rookery
  > `attestation` module is published to the Go proxy, but the attestor
  > *plugin* modules this webhook needs (`policyverify` is mandatory for
  > `workflow.Verify`) declare their `attestation` dependency as the
  > placeholder version `v0.0.0-00010101000000-000000000000`, which only
  > resolves via the monorepo's internal `replace` directives — and Go
  > ignores a dependency's replaces. A proxy-only build therefore fails with
  > `invalid version: unknown revision 000000000000`. Once rookery publishes
  > its plugins with real version requirements, the `replace` block here can
  > simply be deleted.

## Quickstart

```bash
make e2e
```

This runs, in order (see `dev/`):

| step | script | what it does |
|---|---|---|
| `dev-up` | `kind-up.sh` | kind cluster + local registry (`localhost:5001`) |
| `dev-prepare` | `gen-certs.sh`, `attest-demo.sh` | webhook TLS certs; build+push demo image; `cilock run -a oci` over `docker save`; `cilock policy from-bundles` + `cilock sign` |
| `dev-deploy` | `deploy.sh` | build webhook image, `kind load`, deploy webhook + policy + attestations, register the ValidatingWebhookConfiguration |
| `dev-test` | `e2e.sh` | attested image admitted, unattested image denied |

Tear down with `make dev-down`.

Namespaces opt in to enforcement with a label:

```bash
kubectl label namespace my-namespace cilock-policy=enforce
```

## Verifying an image without a cluster

`cilock-k8s` is this repo's binary (not the `cilock` CLI — that one creates
the evidence at build time). Its main mode is `serve`, the admission webhook,
but it doubles as a CLI that runs the exact same verification locally:

```bash
go build -o cilock-k8s .
./cilock-k8s verify \
  --policy policy.signed.json \
  --policy-key policy-pub.pem \
  --attestation-dir attestations/ \
  --insecure-registry localhost:5001 \
  localhost:5001/cilock-demo:1
```

`serve` (the webhook mode) takes the same flags plus `--listen`, `--tls-cert`,
`--tls-key`, and `--registry-alias from=to` for registries that are reachable
under a different name from inside the cluster than the one pod specs use
(e.g. the kind local-registry convention).

## Why the image ID is the join key

`docker save`'s tar and the registry's copy of an image have different
manifest digests, but the **config digest (image ID) is identical** in both.
The `oci` attestor records it as the `imageid` subject at build time, and the
webhook re-derives it from the registry at admission time — so the attestation
made on the build machine binds to the image the node will actually run,
without needing the registry manifest digest at attestation time.

## Platform mode (TestifySec platform integration)

Platform mode connects the webhook to a [TestifySec Judge
platform](https://www.testifysec.com) tenant. It is **opt-in**: without
`--platform-url` the webhook behaves exactly as documented above (file-based
policy, always enforcing, nothing reported) — that is also the offline /
air-gapped mode.

```bash
cilock-k8s serve \
  --platform-url https://judge.example.com \
  --platform-token "$CILOCK_PLATFORM_TOKEN" \   # from registerKubernetesCluster; or env
  --policy policy.signed.json --policy-key policy-pub.pem \
  --attestation-dir attestations
```

What the platform connection does (all connections are opened by the agent,
outward — the platform never dials into the cluster):

- **Registration & heartbeat** — the agent identifies its cluster by the
  `kube-system` namespace UID (auto-detected in-cluster, or `--cluster-uid`)
  and checks in every ~60s. The check-in response carries the cluster's
  **enforcement mode**: `AUDIT` (verify + report, admit everything — the
  default until the first successful check-in), `ENFORCE` (deny on failure),
  or `DISABLED` (stand down).
- **Decision reporting** — every per-container verdict (pass *and* fail) is
  reported, pre-aggregated (identical decisions collapse into one row with an
  occurrence count) and batched, into the platform's admission-decision feed.
- **Policy sync** — when a policy is bound to the cluster on the platform, the
  check-in carries its Archivista gitoid; the agent downloads the signed
  policy envelope, verifies it against `--policy-key`, and hot-swaps the
  verifier without a restart. Rotating a policy on the platform reaches the
  cluster within one poll. A binding's namespace list scopes enforcement;
  pods outside it are admitted and recorded as `NO_POLICY`.

The agent credential is minted by the platform's `registerKubernetesCluster`
mutation, scoped to reporting only (it cannot change its own enforcement mode
or upload attestations), and revoking the cluster on the platform kills it.

## Status / limitations (PoC)

- Attestations and policy are static ConfigMap mounts — no Archivista/Rekor
  lookup yet, so rotating evidence means redeploying the ConfigMaps. (In
  platform mode the *policy* half of this is solved by policy sync; the
  attestation directory is still file-mounted.)
- The policy trusts a single embedded public key (no Fulcio/keyless, no TSA) —
  platform mode keeps this trust model for now: synced policy content comes
  from the platform, but the trust anchor is still `--policy-key`.
- Only `CREATE pod` is validated; higher-level workloads (Deployments etc.)
  are caught when their pods are created.
- Multi-arch indexes resolve to the platform matching the webhook's
  architecture, falling back to the first runnable platform entry.

## Credits

- Original PoC: [testifysec/judge-k8s](https://github.com/testifysec/judge-k8s)
  by [Cole Kennedy](https://github.com/colek42) (TestifySec), built on early
  [witness](https://github.com/testifysec/witness) + Rekor — the git history
  of that work is preserved in this repository.
- Rewritten to use the actively maintained
  [cilock / rookery attestation library](https://github.com/aflock-ai/rookery)
  (the lineage of [go-witness](https://github.com/in-toto/go-witness)).
