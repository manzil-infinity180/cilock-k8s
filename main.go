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
	"strings"
	"time"

	"github.com/manzil-infinity180/cilock-k8s/pkg/handlers"
	"github.com/manzil-infinity180/cilock-k8s/pkg/verify"
)

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

func newVerifier(cf *commonFlags) (*verify.Verifier, error) {
	aliases := map[string]string{}
	for _, alias := range cf.registryAliases {
		from, to, ok := strings.Cut(alias, "=")
		if !ok {
			return nil, fmt.Errorf("invalid --registry-alias %q, expected from=to", alias)
		}
		aliases[from] = to
	}

	return verify.New(verify.Options{
		PolicyPath:         cf.policy,
		PolicyPubKeyPath:   cf.policyKey,
		AttestationDir:     cf.attestationDir,
		InsecureRegistries: cf.insecureRegistries,
		RegistryAliases:    aliases,
	})
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
	_ = fs.Parse(args)

	verifier, err := newVerifier(cf)
	if err != nil {
		log.Fatalf("failed to initialize verifier: %v", err)
	}

	log.Printf("loaded policy %s with %d attestation envelope(s)", cf.policy, len(verifier.AttestationRefs()))

	mux := http.NewServeMux()
	mux.HandleFunc("/validate", handlers.Admission(verifier))
	mux.HandleFunc("/healthz", handlers.Health)

	server := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("listening on %s", *listen)
	if err := server.ListenAndServeTLS(*tlsCert, *tlsKey); err != nil {
		log.Fatalf("server exited: %v", err)
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
