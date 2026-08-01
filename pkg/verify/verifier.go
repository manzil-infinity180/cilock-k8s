// Package verify verifies container images against a signed witness policy
// using the in-toto go-witness library (the engine behind `witness verify`).
package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	// Importing the root package also registers every attestor (including
	// the mandatory policyverify attestor) via its init imports.
	witness "github.com/in-toto/go-witness"
	"github.com/in-toto/go-witness/cryptoutil"
	"github.com/in-toto/go-witness/dsse"
	"github.com/in-toto/go-witness/source"

	"github.com/manzil-infinity180/cilock-k8s/pkg/image"
)

// Options configures a Verifier.
type Options struct {
	// PolicyPath is a signed witness policy (DSSE envelope, JSON).
	PolicyPath string
	// PolicyPubKeyPath is a PEM public key trusted to have signed the policy.
	PolicyPubKeyPath string
	// AttestationDir holds DSSE attestation envelopes (*.json), e.g. the
	// output of `cilock run -o build.att.json`.
	AttestationDir string
	// InsecureRegistries lists registry hosts to contact over plain HTTP.
	InsecureRegistries []string
	// RegistryAliases maps a registry host as it appears in pod image refs to
	// the host the webhook should actually dial (e.g. "localhost:5001" ->
	// "172.18.0.2:5000" for a kind local registry).
	RegistryAliases map[string]string
}

// Verifier verifies image references against the configured policy.
type Verifier struct {
	policyEnvelope  dsse.Envelope
	policyVerifiers []cryptoutil.Verifier
	collectionSrc   source.Sourcer
	resolver        *image.Resolver
	attestationRefs []string
}

// New loads the policy, trusted public key, and attestation envelopes.
func New(o Options) (*Verifier, error) {
	policyBytes, err := os.ReadFile(o.PolicyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	policyEnvelope := dsse.Envelope{}
	if err := json.Unmarshal(policyBytes, &policyEnvelope); err != nil {
		return nil, fmt.Errorf("failed to parse policy file %q as a DSSE envelope: %w", o.PolicyPath, err)
	}

	keyFile, err := os.Open(o.PolicyPubKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open policy public key: %w", err)
	}
	defer keyFile.Close()

	verifier, err := cryptoutil.NewVerifierFromReader(keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load policy public key %q: %w", o.PolicyPubKeyPath, err)
	}

	memSource := source.NewMemorySource()
	refs := []string{}
	err = filepath.WalkDir(o.AttestationDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			// Skip kubernetes volume internals (..data, ..<timestamp>) so
			// each projected file is only loaded once, via its visible name.
			if strings.HasPrefix(d.Name(), "..") {
				return fs.SkipDir
			}
			return nil
		}

		if !strings.HasSuffix(path, ".json") {
			return nil
		}

		if err := memSource.LoadFile(path); err != nil {
			return fmt.Errorf("failed to load attestation %q: %w", path, err)
		}

		refs = append(refs, path)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load attestations from %q: %w", o.AttestationDir, err)
	}

	if len(refs) == 0 {
		return nil, fmt.Errorf("no attestation envelopes (*.json) found in %q", o.AttestationDir)
	}

	return &Verifier{
		policyEnvelope:  policyEnvelope,
		policyVerifiers: []cryptoutil.Verifier{verifier},
		collectionSrc:   memSource,
		resolver: &image.Resolver{
			InsecureRegistries: o.InsecureRegistries,
			RegistryAliases:    o.RegistryAliases,
		},
		attestationRefs: refs,
	}, nil
}

// AttestationRefs returns the references of the loaded attestation envelopes.
func (v *Verifier) AttestationRefs() []string {
	return v.attestationRefs
}

// Result describes a successful verification of one image.
type Result struct {
	ImageRef string
	Digests  image.Digests
	// StepNames lists the policy steps that were satisfied.
	StepNames []string
}

// VerifyImage resolves imageRef to its digests and verifies them against the
// policy. A nil error means the policy passed.
func (v *Verifier) VerifyImage(ctx context.Context, imageRef string) (*Result, error) {
	digests, err := v.resolver.Resolve(ctx, imageRef)
	if err != nil {
		return nil, err
	}

	subjects, err := digests.SubjectDigestSets()
	if err != nil {
		return nil, err
	}

	verifyResult, err := witness.Verify(ctx, v.policyEnvelope, v.policyVerifiers,
		witness.VerifyWithSubjectDigests(subjects),
		witness.VerifyWithCollectionSource(v.collectionSrc),
	)
	if err != nil {
		return nil, fmt.Errorf("image %s (%s) failed policy verification: %w", imageRef, digests, err)
	}

	result := &Result{ImageRef: imageRef, Digests: digests}
	for stepName := range verifyResult.StepResults {
		result.StepNames = append(result.StepNames, stepName)
	}

	return result, nil
}
