package platform

import (
	"context"
	"log"
	"sync"
	"time"

	"github.com/manzil-infinity180/cilock-k8s/pkg/verify"
)

// PolicySync keeps the webhook's verifier in step with the policy the platform
// says is bound to this cluster. On every check-in it receives the bound
// policy reference; when the referenced DSSE gitoid changes it downloads the
// signed policy envelope from Archivista, builds a replacement verifier
// (which re-verifies the policy signature against the trusted public key on
// first use, exactly as the file-based path does), and hot-swaps it in.
//
// TRUST MODEL (phase 1 of enforcement): the policy CONTENT comes from the
// platform, but the trust anchor is still the operator-provided public key
// (--policy-key) mounted to the webhook — the same key the file-based mode
// uses. A policy whose signature the key rejects fails at verification time
// and the previous verifier stays active. Platform-CA (keyless) policy trust
// is a documented follow-up.
//
// FAILURE SEMANTICS: sync failures never brick admission. Download or parse
// failure keeps the current verifier and retries on the next check-in; a
// binding REMOVED on the platform reverts the webhook to its boot-time
// (file-based) verifier when one exists, and otherwise keeps the last synced
// policy with a warning — dropping the verifier entirely would fail every
// admission in enforce mode on a platform hiccup.
type PolicySync struct {
	client    *Client
	swap      *verify.Swappable
	buildOpts verify.Options

	mu            sync.Mutex
	currentGitoid string
	bootVerifier  *verify.Verifier // the file-based verifier from startup; may be nil
}

// NewPolicySync wires policy sync over an existing swappable verifier.
// buildOpts carries the non-policy options (public key path, attestation dir,
// registry settings) used to construct each synced verifier; bootVerifier is
// the file-based verifier the webhook started with (nil when the deployment is
// platform-only).
func NewPolicySync(client *Client, swap *verify.Swappable, buildOpts verify.Options, bootVerifier *verify.Verifier) *PolicySync {
	return &PolicySync{
		client:       client,
		swap:         swap,
		buildOpts:    buildOpts,
		bootVerifier: bootVerifier,
	}
}

// Apply is the OnBoundPolicy callback: reconcile the running verifier with the
// platform's bound policy. Cheap no-op when nothing changed.
func (s *PolicySync) Apply(ctx context.Context, bp *BoundPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if bp == nil {
		if s.currentGitoid == "" {
			return // never synced, nothing to revert
		}
		if s.bootVerifier != nil {
			s.swap.Swap(s.bootVerifier)
			log.Printf("policysync: binding removed on platform — reverted to the boot-time file policy")
		} else {
			log.Printf("policysync: WARNING binding removed on platform but no file policy to revert to — keeping last synced policy (gitoid %s)", s.currentGitoid)
			return // keep currentGitoid so a re-bind of the same policy still no-ops correctly
		}
		s.currentGitoid = ""
		return
	}

	if bp.DsseGitoidSha256 == s.currentGitoid {
		return // already running this policy
	}

	dlCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	envelope, err := s.client.DownloadGitoid(dlCtx, bp.DsseGitoidSha256)
	if err != nil {
		log.Printf("policysync: keeping current policy, download of %s (release %s) failed: %v", bp.DsseGitoidSha256, bp.Tag, err)
		return
	}

	next, err := verify.NewFromPolicyBytes(envelope, s.buildOpts)
	if err != nil {
		log.Printf("policysync: keeping current policy, downloaded policy %s (release %s) rejected: %v", bp.DsseGitoidSha256, bp.Tag, err)
		return
	}

	s.swap.Swap(next)
	s.currentGitoid = bp.DsseGitoidSha256
	tag := bp.Tag
	if tag == "" {
		tag = "(untagged)"
	}
	log.Printf("policysync: now enforcing platform policy release %s (gitoid %s, namespaces %v)", tag, bp.DsseGitoidSha256, bp.Namespaces)
}
