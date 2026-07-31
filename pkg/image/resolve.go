// Package image resolves container image references to the content digests
// that witness/cilock attestations record as subjects.
package image

import (
	"context"
	"crypto"
	"fmt"
	"runtime"
	"strings"

	"github.com/aflock-ai/rookery/attestation/cryptoutil"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// Digests holds the digests of an image that can be matched against
// attestation subjects. ManifestDigest is the registry manifest digest
// (what `image@sha256:...` pins). ConfigDigest is the image ID — the digest
// of the image config blob. The image ID is the same whether the image was
// attested from a `docker save` tar (cilock's oci attestor records it as the
// `imageid` subject) or pulled from a registry, which makes it the reliable
// join key between build-time attestations and the image a pod runs.
type Digests struct {
	ManifestDigest string
	ConfigDigest   string
}

// Resolver resolves image references against their registry.
type Resolver struct {
	// InsecureRegistries lists registry hosts (host or host:port) that should
	// be contacted over plain HTTP, e.g. an in-cluster development registry.
	InsecureRegistries []string
	// RegistryAliases rewrites a registry host before resolving. Needed when
	// pods reference a registry by a name that is not reachable from the
	// webhook pod — e.g. the kind local-registry convention, where nodes pull
	// "localhost:5001/..." but the webhook must dial the registry container's
	// address on the docker network instead.
	RegistryAliases map[string]string
}

func (r *Resolver) parseRef(imageRef string) (name.Reference, error) {
	for from, to := range r.RegistryAliases {
		if rest, ok := strings.CutPrefix(imageRef, from+"/"); ok {
			imageRef = to + "/" + rest
			break
		}
	}

	opts := []name.Option{}
	for _, reg := range r.InsecureRegistries {
		if strings.HasPrefix(imageRef, reg+"/") {
			opts = append(opts, name.Insecure)
			break
		}
	}

	return name.ParseReference(imageRef, opts...)
}

// Resolve fetches the manifest for imageRef and returns its digests. Manifest
// lists are resolved to the linux platform image matching the digest's first
// available platform entry.
func (r *Resolver) Resolve(ctx context.Context, imageRef string) (Digests, error) {
	ref, err := r.parseRef(imageRef)
	if err != nil {
		return Digests{}, fmt.Errorf("invalid image reference %q: %w", imageRef, err)
	}

	desc, err := remote.Get(ref,
		remote.WithContext(ctx),
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	)
	if err != nil {
		return Digests{}, fmt.Errorf("failed to fetch image %q: %w", imageRef, err)
	}

	img, err := descriptorToImage(desc)
	if err != nil {
		return Digests{}, fmt.Errorf("failed to resolve image %q: %w", imageRef, err)
	}

	manifestDigest, err := img.Digest()
	if err != nil {
		return Digests{}, fmt.Errorf("failed to get manifest digest for %q: %w", imageRef, err)
	}

	configDigest, err := img.ConfigName()
	if err != nil {
		return Digests{}, fmt.Errorf("failed to get config digest for %q: %w", imageRef, err)
	}

	return Digests{
		ManifestDigest: manifestDigest.String(),
		ConfigDigest:   configDigest.String(),
	}, nil
}

// SubjectDigestSets converts the resolved digests into cryptoutil digest sets
// suitable for workflow.VerifyWithSubjectDigests.
func (d Digests) SubjectDigestSets() ([]cryptoutil.DigestSet, error) {
	sets := []cryptoutil.DigestSet{}
	for _, digest := range []string{d.ConfigDigest, d.ManifestDigest} {
		hex, err := sha256Hex(digest)
		if err != nil {
			return nil, err
		}

		sets = append(sets, cryptoutil.DigestSet{
			{Hash: crypto.SHA256}: hex,
		})
	}

	return sets, nil
}

// descriptorToImage returns the manifest the pod would actually run: the
// descriptor itself when it is a single image, or for a manifest list / OCI
// index the entry matching the local platform, falling back to the first
// entry that names a real platform (buildkit attestation manifests advertise
// platform unknown/unknown and are skipped).
func descriptorToImage(desc *remote.Descriptor) (v1.Image, error) {
	if !desc.MediaType.IsIndex() {
		return desc.Image()
	}

	idx, err := desc.ImageIndex()
	if err != nil {
		return nil, err
	}

	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}

	var fallback *v1.Hash
	for _, m := range manifest.Manifests {
		p := m.Platform
		if p == nil || p.OS == "" || p.OS == "unknown" {
			continue
		}

		if p.OS == "linux" && p.Architecture == runtime.GOARCH {
			return idx.Image(m.Digest)
		}

		if fallback == nil {
			digest := m.Digest
			fallback = &digest
		}
	}

	if fallback == nil {
		return nil, fmt.Errorf("image index contains no runnable platform manifests")
	}

	return idx.Image(*fallback)
}

func sha256Hex(digest string) (string, error) {
	hex, ok := strings.CutPrefix(digest, "sha256:")
	if !ok {
		return "", fmt.Errorf("unsupported digest algorithm in %q, only sha256 is supported", digest)
	}

	return hex, nil
}

func (d Digests) String() string {
	return fmt.Sprintf("manifest=%s imageid=%s", d.ManifestDigest, d.ConfigDigest)
}
