package verify

import (
	"context"
	"sync/atomic"
)

// ImageVerifier is the capability the admission handler needs: verify one
// image reference against the current policy. *Verifier implements it; so does
// *Swappable, which is how platform policy-sync replaces the policy at runtime
// without restarting the webhook.
type ImageVerifier interface {
	VerifyImage(ctx context.Context, imageRef string) (*Result, error)
}

// Swappable is an ImageVerifier whose underlying Verifier can be replaced
// atomically. Admission requests in flight keep the verifier they started
// with; new requests see the new policy immediately after Swap returns.
type Swappable struct {
	current atomic.Pointer[Verifier]
}

// NewSwappable wraps an initial verifier (which may come from the file-based
// flags, or the first synced platform policy).
func NewSwappable(initial *Verifier) *Swappable {
	s := &Swappable{}
	s.current.Store(initial)
	return s
}

// VerifyImage delegates to the current verifier.
func (s *Swappable) VerifyImage(ctx context.Context, imageRef string) (*Result, error) {
	return s.current.Load().VerifyImage(ctx, imageRef)
}

// Swap replaces the underlying verifier for all future admissions.
func (s *Swappable) Swap(v *Verifier) {
	s.current.Store(v)
}

// Current returns the verifier future admissions would use; policy-sync uses
// it to rebuild with the same options.
func (s *Swappable) Current() *Verifier {
	return s.current.Load()
}
