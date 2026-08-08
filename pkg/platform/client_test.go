package platform

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakePlatform is a minimal judge-platform stand-in: discovery doc + a GraphQL
// endpoint whose behavior each test scripts.
type fakePlatform struct {
	t *testing.T

	mu       sync.Mutex
	requests []graphqlRequest
	handler  func(req graphqlRequest) (any, []string) // returns data, errors

	server *httptest.Server
}

type graphqlRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

func newFakePlatform(t *testing.T) *fakePlatform {
	f := &fakePlatform{t: t}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/judge-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"graphql_url":    f.server.URL + "/query",
			"archivista_url": f.server.URL,
		})
	})
	mux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			http.Error(w, "bad token: "+got, http.StatusUnauthorized)
			return
		}
		req := graphqlRequest{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f.mu.Lock()
		f.requests = append(f.requests, req)
		handler := f.handler
		f.mu.Unlock()

		data, errs := handler(req)
		resp := map[string]any{"data": data}
		if len(errs) > 0 {
			es := make([]map[string]string, 0, len(errs))
			for _, e := range errs {
				es = append(es, map[string]string{"message": e})
			}
			resp["errors"] = es
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakePlatform) setHandler(h func(req graphqlRequest) (any, []string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.handler = h
}

func (f *fakePlatform) recorded() []graphqlRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]graphqlRequest{}, f.requests...)
}

func newTestClient(t *testing.T, f *fakePlatform) *Client {
	c, err := New(context.Background(), Config{
		PlatformURL:  f.server.URL,
		Token:        "test-token",
		ClusterUID:   "uid-123",
		AgentVersion: "test",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func checkInOK(mode string) func(req graphqlRequest) (any, []string) {
	return func(req graphqlRequest) (any, []string) {
		return map[string]any{"clusterAgentCheckIn": map[string]any{
			"clusterID":       "cid-1",
			"enforcementMode": mode,
		}}, nil
	}
}

func TestModeDefaultsToAuditBeforeFirstCheckIn(t *testing.T) {
	f := newFakePlatform(t)
	f.setHandler(checkInOK("ENFORCE"))
	c := newTestClient(t, f)

	if got := c.Mode(); got != ModeAudit {
		t.Fatalf("mode before check-in = %q, want %q (an unreachable platform must not brick deploys)", got, ModeAudit)
	}

	if err := c.CheckIn(context.Background()); err != nil {
		t.Fatalf("CheckIn: %v", err)
	}
	if got := c.Mode(); got != ModeEnforce {
		t.Fatalf("mode after check-in = %q, want ENFORCE", got)
	}
}

func TestRecordAggregatesIdenticalDecisions(t *testing.T) {
	f := newFakePlatform(t)
	f.setHandler(checkInOK("AUDIT"))
	c := newTestClient(t, f)

	d := Decision{
		Namespace: "prod", ImageRef: "app:v1", ImageDigest: "sha256:aaa",
		Verdict: VerdictFail, Action: ActionAdmitted, Mode: ModeAudit, Reason: "no attestations",
	}
	for i := 0; i < 3; i++ {
		d.At = time.Date(2026, 8, 8, 1, 0, i, 0, time.UTC)
		c.Record(d)
	}
	other := d
	other.Namespace = "staging"
	c.Record(other)

	c.queueMu.Lock()
	defer c.queueMu.Unlock()
	if len(c.queue) != 2 {
		t.Fatalf("queue size = %d, want 2 (3 identical collapse + 1 distinct)", len(c.queue))
	}
	for _, agg := range c.queue {
		switch agg.Namespace {
		case "prod":
			if agg.count != 3 {
				t.Errorf("prod count = %d, want 3", agg.count)
			}
			if !agg.lastSeen.After(agg.firstSeen) {
				t.Errorf("window bounds not tracked: first=%v last=%v", agg.firstSeen, agg.lastSeen)
			}
		case "staging":
			if agg.count != 1 {
				t.Errorf("staging count = %d, want 1", agg.count)
			}
		}
	}
}

func TestFlushReportsAggregatesAndClearsQueue(t *testing.T) {
	f := newFakePlatform(t)
	f.setHandler(func(req graphqlRequest) (any, []string) {
		if strings.Contains(req.Query, "ReportAdmissionDecisions") {
			input := req.Variables["input"].(map[string]any)
			decisions := input["decisions"].([]any)
			return map[string]any{"reportAdmissionDecisions": map[string]any{
				"accepted": len(decisions),
			}}, nil
		}
		return nil, []string{"unexpected query"}
	})
	c := newTestClient(t, f)

	for i := 0; i < 3; i++ {
		c.Record(Decision{Namespace: "prod", ImageRef: "app:v1", Verdict: VerdictPass, Action: ActionAdmitted, Mode: ModeAudit})
	}

	if err := c.Flush(context.Background()); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	var report *graphqlRequest
	for i := range f.recorded() {
		if strings.Contains(f.recorded()[i].Query, "ReportAdmissionDecisions") {
			report = &f.recorded()[i]
		}
	}
	if report == nil {
		t.Fatal("no report mutation reached the platform")
	}
	input := report.Variables["input"].(map[string]any)
	if got := input["clusterUID"]; got != "uid-123" {
		t.Errorf("clusterUID = %v, want uid-123", got)
	}
	decisions := input["decisions"].([]any)
	if len(decisions) != 1 {
		t.Fatalf("reported %d decisions, want 1 aggregated row", len(decisions))
	}
	row := decisions[0].(map[string]any)
	if got := row["occurrenceCount"]; got != float64(3) {
		t.Errorf("occurrenceCount = %v, want 3", got)
	}

	c.queueMu.Lock()
	defer c.queueMu.Unlock()
	if len(c.queue) != 0 {
		t.Errorf("queue not cleared after successful flush: %d rows", len(c.queue))
	}
}

func TestFlushFailureRequeuesForRetry(t *testing.T) {
	f := newFakePlatform(t)
	f.setHandler(func(req graphqlRequest) (any, []string) {
		return nil, []string{"boom"}
	})
	c := newTestClient(t, f)

	c.Record(Decision{Namespace: "prod", ImageRef: "app:v1", Verdict: VerdictPass, Action: ActionAdmitted, Mode: ModeAudit})

	if err := c.Flush(context.Background()); err == nil {
		t.Fatal("Flush should fail when the platform errors")
	}

	c.queueMu.Lock()
	defer c.queueMu.Unlock()
	if len(c.queue) != 1 {
		t.Fatalf("failed flush must requeue: queue = %d rows, want 1", len(c.queue))
	}
}

func TestCheckInFallsBackWhenServerLacksBoundPolicy(t *testing.T) {
	f := newFakePlatform(t)
	f.setHandler(func(req graphqlRequest) (any, []string) {
		if strings.Contains(req.Query, "boundPolicy") {
			return nil, []string{`Cannot query field "boundPolicy" on type "ClusterAgentCheckInPayload".`}
		}
		return map[string]any{"clusterAgentCheckIn": map[string]any{
			"clusterID":       "cid-1",
			"enforcementMode": "AUDIT",
		}}, nil
	})
	c := newTestClient(t, f)

	if err := c.CheckIn(context.Background()); err != nil {
		t.Fatalf("CheckIn should downgrade to the legacy query, got: %v", err)
	}
	if !c.legacyCheckIn {
		t.Error("legacyCheckIn flag not set after downgrade")
	}
	if bp := c.BoundPolicy(); bp != nil {
		t.Errorf("BoundPolicy = %+v, want nil on a pre-binding server", bp)
	}

	// Subsequent check-ins must go straight to the legacy query.
	before := len(f.recorded())
	if err := c.CheckIn(context.Background()); err != nil {
		t.Fatalf("second CheckIn: %v", err)
	}
	reqs := f.recorded()[before:]
	if len(reqs) != 1 || strings.Contains(reqs[0].Query, "boundPolicy") {
		t.Errorf("second check-in should be a single legacy query, got %d request(s)", len(reqs))
	}
}

func TestCheckInAppliesBoundPolicyAndInvokesCallback(t *testing.T) {
	f := newFakePlatform(t)
	f.setHandler(func(req graphqlRequest) (any, []string) {
		return map[string]any{"clusterAgentCheckIn": map[string]any{
			"clusterID":       "cid-1",
			"enforcementMode": "ENFORCE",
			"boundPolicy": map[string]any{
				"policyReleaseID":  "rel-1",
				"tag":              "v1.2.0",
				"dsseGitoidSha256": "gitoid-abc",
				"namespaces":       []string{"prod", "payments"},
			},
		}}, nil
	})
	c := newTestClient(t, f)

	var got *BoundPolicy
	c.SetOnBoundPolicy(func(_ context.Context, bp *BoundPolicy) { got = bp })

	if err := c.CheckIn(context.Background()); err != nil {
		t.Fatalf("CheckIn: %v", err)
	}
	if got == nil || got.DsseGitoidSha256 != "gitoid-abc" {
		t.Fatalf("callback bound policy = %+v, want gitoid-abc", got)
	}
	if ns := c.PolicyNamespaces(); len(ns) != 2 || ns[0] != "prod" {
		t.Errorf("PolicyNamespaces = %v, want [prod payments]", ns)
	}
}

func TestDownloadGitoidUsesAgentToken(t *testing.T) {
	f := newFakePlatform(t)
	f.setHandler(checkInOK("AUDIT"))

	f.server.Config.Handler.(*http.ServeMux).HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		fmt.Fprint(w, `{"payload":"fake"}`)
	})

	c := newTestClient(t, f)
	body, err := c.DownloadGitoid(context.Background(), "gitoid-abc")
	if err != nil {
		t.Fatalf("DownloadGitoid: %v", err)
	}
	if !strings.Contains(string(body), "fake") {
		t.Errorf("unexpected body: %s", body)
	}
}
