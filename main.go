// cilock-k8s is a proof-of-concept Kubernetes validating admission webhook
// that verifies container images against a signed witness/cilock policy.
//
// Subcommands:
//
//	serve   run the admission webhook server
//	verify  verify a single image reference locally and exit
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/manzil-infinity180/cilock-k8s/pkg/handlers"
	"github.com/manzil-infinity180/cilock-k8s/pkg/platform"
	"github.com/manzil-infinity180/cilock-k8s/pkg/verify"
)

// agentVersion is reported to the platform on every check-in. Overridden at
// release time via -ldflags "-X main.agentVersion=...".
var agentVersion = "0.1.0-dev"

type commonFlags struct {
	policy             string
	policyKey          string
	attestationDir     string
	insecureRegistries stringSlice
	registryAliases    stringSlice
}

type stringSlice []string

func (s *stringSlice) String() string { return fmt.Sprint(*s) }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func registerCommonFlags(fs *flag.FlagSet, cf *commonFlags) {
	fs.StringVar(&cf.policy, "policy", "policy.signed.json", "path to the signed witness policy (DSSE envelope)")
	fs.StringVar(&cf.policyKey, "policy-key", "policy-pub.pem", "path to the PEM public key trusted to sign the policy")
	fs.StringVar(&cf.attestationDir, "attestation-dir", "attestations", "directory of DSSE attestation envelopes (*.json)")
	fs.Var(&cf.insecureRegistries, "insecure-registry", "registry host to contact over plain HTTP (repeatable)")
	fs.Var(&cf.registryAliases, "registry-alias", "rewrite a registry host before resolving, as from=to (repeatable)")
}

func verifierOptions(cf *commonFlags) (verify.Options, error) {
	aliases := map[string]string{}
	for _, alias := range cf.registryAliases {
		from, to, ok := strings.Cut(alias, "=")
		if !ok {
			return verify.Options{}, fmt.Errorf("invalid --registry-alias %q, expected from=to", alias)
		}
		aliases[from] = to
	}

	return verify.Options{
		PolicyPath:         cf.policy,
		PolicyPubKeyPath:   cf.policyKey,
		AttestationDir:     cf.attestationDir,
		InsecureRegistries: cf.insecureRegistries,
		RegistryAliases:    aliases,
	}, nil
}

func newVerifier(cf *commonFlags) (*verify.Verifier, error) {
	o, err := verifierOptions(cf)
	if err != nil {
		return nil, err
	}
	return verify.New(o)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "serve":
		serveCmd(os.Args[2:])
	case "verify":
		verifyCmd(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: cilock-k8s serve [flags] | cilock-k8s verify [flags] <image-ref>")
}

func serveCmd(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cf := &commonFlags{}
	registerCommonFlags(fs, cf)
	listen := fs.String("listen", ":8443", "address to listen on")
	tlsCert := fs.String("tls-cert", "/etc/webhook/certs/tls.crt", "path to the TLS certificate")
	tlsKey := fs.String("tls-key", "/etc/webhook/certs/tls.key", "path to the TLS private key")
	platformURL := fs.String("platform-url", "", "TestifySec platform base URL; empty runs the original file-only mode")
	platformToken := fs.String("platform-token", "", "agent credential from registerKubernetesCluster (or env CILOCK_PLATFORM_TOKEN)")
	clusterUID := fs.String("cluster-uid", "", "kube-system namespace UID; auto-detected in-cluster when empty")
	_ = fs.Parse(args)

	verifier, err := newVerifier(cf)
	if err != nil {
		log.Fatalf("failed to initialize verifier: %v", err)
	}

	log.Printf("loaded policy %s with %d attestation envelope(s)", cf.policy, len(verifier.AttestationRefs()))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Platform mode is opt-in: without --platform-url the webhook behaves
	// exactly like the original PoC (file-based policy, always enforcing,
	// nothing reported). This is also the offline/air-gapped mode.
	var pc *platform.Client
	if *platformURL != "" {
		token := *platformToken
		if token == "" {
			token = os.Getenv("CILOCK_PLATFORM_TOKEN")
		}
		if token == "" {
			log.Fatalf("--platform-url is set but no credential given: pass --platform-token or set CILOCK_PLATFORM_TOKEN")
		}

		uid := *clusterUID
		if uid == "" {
			detected, err := platform.DetectClusterUID(ctx)
			if err != nil {
				log.Fatalf("failed to detect cluster UID (pass --cluster-uid explicitly): %v", err)
			}
			uid = detected
		}

		pc, err = platform.New(ctx, platform.Config{
			PlatformURL:  *platformURL,
			Token:        token,
			ClusterUID:   uid,
			AgentVersion: agentVersion,
		})
		if err != nil {
			log.Fatalf("failed to initialize platform client: %v", err)
		}

		log.Printf("platform mode: reporting to %s as cluster %s (mode %s until first check-in)", *platformURL, uid, pc.Mode())
	}

	// The webhook verifies through a swappable wrapper so platform policy-sync
	// can replace the policy at runtime; without a platform it is a zero-cost
	// indirection over the file-based verifier.
	swap := verify.NewSwappable(verifier)
	if pc != nil {
		opts, err := verifierOptions(cf)
		if err != nil {
			log.Fatalf("failed to build verifier options for policy sync: %v", err)
		}
		sync := platform.NewPolicySync(pc, swap, opts, verifier)
		pc.SetOnBoundPolicy(sync.Apply)
	}

	// pcDone closes once the platform client has made its final flush after
	// ctx is cancelled; already closed when running without a platform.
	pcDone := make(chan struct{})
	if pc != nil {
		go func() {
			pc.Run(ctx)
			close(pcDone)
		}()
	} else {
		close(pcDone)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", handlers.Admission(swap, pc))
	mux.HandleFunc("/healthz", handlers.Health)

	server := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("listening on %s", *listen)
		serverErr <- server.ListenAndServeTLS(*tlsCert, *tlsKey)
	}()

	select {
	case err := <-serverErr:
		log.Fatalf("server exited: %v", err)
	case <-ctx.Done():
		// SIGTERM during rollout: stop accepting reviews, then give the
		// platform client's final flush (triggered by the same ctx) a moment
		// so the last decision window is not lost.
		log.Printf("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		select {
		case <-pcDone:
		case <-shutdownCtx.Done():
			log.Printf("gave up waiting for the final decision flush")
		}
	}
}

func verifyCmd(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	cf := &commonFlags{}
	registerCommonFlags(fs, cf)
	timeout := fs.Duration("timeout", 60*time.Second, "verification timeout")
	_ = fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: cilock-k8s verify [flags] <image-ref>")
		os.Exit(2)
	}

	verifier, err := newVerifier(cf)
	if err != nil {
		log.Fatalf("failed to initialize verifier: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	result, err := verifier.VerifyImage(ctx, fs.Arg(0))
	if err != nil {
		log.Fatalf("DENIED: %v", err)
	}

	log.Printf("ALLOWED: image %s (%s) passed policy, steps=%v", result.ImageRef, result.Digests, result.StepNames)
}
