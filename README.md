# cilock-k8s

**Proof-of-concept Kubernetes validating admission webhook that only admits
pods whose container images have verifiable [witness](https://witness.dev)
/ [cilock](https://github.com/aflock-ai/rookery) attestations.**

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

## Status / limitations (PoC)

- Attestations and policy are static ConfigMap mounts — no Archivista/Rekor
  lookup yet, so rotating evidence means redeploying the ConfigMaps.
- The policy trusts a single embedded public key (no Fulcio/keyless, no TSA).
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
