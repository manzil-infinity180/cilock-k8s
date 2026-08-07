// Package platform connects the admission webhook to the TestifySec platform.
//
// Every connection is opened by the agent, outward (egress-only): the periodic
// check-in doubles as the configuration poll — the request carries "I'm alive,
// version X" and the response carries the enforcement mode the webhook must
// apply — and admission decisions are pre-aggregated and pushed in batches.
// The platform never dials into the cluster.
//
// The package is optional: a Verifier-only deployment (no --platform-url)
// behaves exactly like the original file-based PoC.
package platform

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Enforcement modes and decision enums, as the platform's GraphQL schema spells
// them (uppercase enum values, matching e.g. APITokenType's OAUTH/OIDC).
const (
	ModeAudit    = "AUDIT"
	ModeEnforce  = "ENFORCE"
	ModeDisabled = "DISABLED"

	VerdictPass     = "PASS"
	VerdictFail     = "FAIL"
	VerdictError    = "ERROR"
	VerdictNoPolicy = "NO_POLICY"

	ActionAdmitted = "ADMITTED"
	ActionDenied   = "DENIED"
)

// Config configures a Client.
type Config struct {
	// PlatformURL is the base URL of the platform, e.g.
	// https://judge.testifysec.com. The GraphQL endpoint is derived from the
	// discovery document at /.well-known/judge-configuration.
	PlatformURL string
	// Token is the cluster's agent credential, minted by
	// registerKubernetesCluster and scoped to cluster:report.
	Token string
	// ClusterUID is the kube-system namespace UID identifying this cluster.
	ClusterUID string
	// AgentVersion is reported on every check-in.
	AgentVersion string

	// CheckInInterval defaults to 60s.
	CheckInInterval time.Duration
	// FlushInterval defaults to 30s.
	FlushInterval time.Duration
	// MaxBatch caps the decisions sent per report. Defaults to 100.
	MaxBatch int
	// MaxQueue caps distinct aggregated decisions held while the platform is
	// unreachable. Beyond it the oldest rows are dropped (and counted in the
	// log). Defaults to 5000.
	MaxQueue int

	// HTTPClient overrides the default client (10s timeout).
	HTTPClient *http.Client
}

// Decision is one admission verdict for one container, as recorded by the
// webhook handler. Identical decisions inside a flush window are aggregated
// into a single reported row.
type Decision struct {
	Namespace    string
	WorkloadKind string
	WorkloadName string
	ImageRef     string
	ImageDigest  string
	ImageID      string
	Verdict      string
	Action       string
	Mode         string
	Reason       string
	At           time.Time
}

type aggregated struct {
	Decision
	count     int
	firstSeen time.Time
	lastSeen  time.Time
}

// Client is the agent-side platform connection. Safe for concurrent use by the
// webhook handler and the Run loop.
type Client struct {
	cfg        Config
	graphqlURL string
	http       *http.Client

	modeMu sync.RWMutex
	mode   string

	queueMu sync.Mutex
	queue   map[string]*aggregated
	dropped int
}

// discoveryDoc is the subset of /.well-known/judge-configuration the agent
// needs. Field names mirror cilock's internal/config/discovery.go.
type discoveryDoc struct {
	GraphQLURL string `json:"graphql_url"`
}

// New builds a Client and resolves the GraphQL endpoint from the platform's
// discovery document. It does NOT check in; call Run for that.
func New(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.PlatformURL == "" {
		return nil, fmt.Errorf("platform: PlatformURL is required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("platform: Token is required")
	}
	if cfg.ClusterUID == "" {
		return nil, fmt.Errorf("platform: ClusterUID is required")
	}
	if cfg.CheckInInterval <= 0 {
		cfg.CheckInInterval = 60 * time.Second
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 30 * time.Second
	}
	if cfg.MaxBatch <= 0 {
		cfg.MaxBatch = 100
	}
	if cfg.MaxQueue <= 0 {
		cfg.MaxQueue = 5000
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}

	c := &Client{
		cfg: cfg,
		// Fail-open until the first successful check-in: an agent that cannot
		// reach the platform yet must not brick deploys with a mode it never
		// learned. The platform-side default for a fresh cluster is AUDIT too.
		mode:  ModeAudit,
		http:  cfg.HTTPClient,
		queue: map[string]*aggregated{},
	}

	base := strings.TrimRight(cfg.PlatformURL, "/")
	doc, err := c.discover(ctx, base)
	if err != nil {
		return nil, err
	}
	c.graphqlURL = doc.GraphQLURL
	if c.graphqlURL == "" {
		c.graphqlURL = base + "/query"
	}

	return c, nil
}

func (c *Client) discover(ctx context.Context, base string) (*discoveryDoc, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/.well-known/judge-configuration", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("platform: discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("platform: discovery returned %s", resp.Status)
	}

	doc := &discoveryDoc{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(doc); err != nil {
		return nil, fmt.Errorf("platform: failed to parse discovery document: %w", err)
	}

	return doc, nil
}

// Mode returns the enforcement mode from the most recent successful check-in,
// or AUDIT if the platform has not been reached yet.
func (c *Client) Mode() string {
	c.modeMu.RLock()
	defer c.modeMu.RUnlock()
	return c.mode
}

// Record queues one decision for the next batched report. Identical decisions
// (same identity, verdict, action, mode, and reason) collapse into a single
// row with an occurrence count — a crash-looping pod is one fact, not one row
// per restart.
func (c *Client) Record(d Decision) {
	if d.At.IsZero() {
		d.At = time.Now().UTC()
	}

	key := strings.Join([]string{
		d.Namespace, d.WorkloadKind, d.WorkloadName,
		d.ImageRef, d.ImageDigest,
		d.Verdict, d.Action, d.Mode, d.Reason,
	}, "\x1f")

	c.queueMu.Lock()
	defer c.queueMu.Unlock()

	if agg, ok := c.queue[key]; ok {
		agg.count++
		if d.At.After(agg.lastSeen) {
			agg.lastSeen = d.At
		}
		return
	}

	if len(c.queue) >= c.cfg.MaxQueue {
		c.evictOldestLocked()
	}

	c.queue[key] = &aggregated{Decision: d, count: 1, firstSeen: d.At, lastSeen: d.At}
}

// evictOldestLocked drops the aggregate with the oldest lastSeen. Called with
// queueMu held, only when the platform has been unreachable long enough to
// fill MaxQueue.
func (c *Client) evictOldestLocked() {
	oldestKey := ""
	var oldest time.Time
	for k, agg := range c.queue {
		if oldestKey == "" || agg.lastSeen.Before(oldest) {
			oldestKey, oldest = k, agg.lastSeen
		}
	}
	if oldestKey != "" {
		delete(c.queue, oldestKey)
		c.dropped++
	}
}

// Run drives the check-in and report loops until ctx is cancelled, then makes
// one final best-effort flush so a terminating pod does not lose its window.
func (c *Client) Run(ctx context.Context) {
	if err := c.CheckIn(ctx); err != nil {
		log.Printf("platform: initial check-in failed (staying in %s until the platform is reachable): %v", c.Mode(), err)
	}

	checkIn := time.NewTicker(c.cfg.CheckInInterval)
	flush := time.NewTicker(c.cfg.FlushInterval)
	defer checkIn.Stop()
	defer flush.Stop()

	for {
		select {
		case <-ctx.Done():
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := c.Flush(flushCtx); err != nil {
				log.Printf("platform: final flush failed: %v", err)
			}
			return
		case <-checkIn.C:
			if err := c.CheckIn(ctx); err != nil {
				log.Printf("platform: check-in failed (keeping mode %s): %v", c.Mode(), err)
			}
		case <-flush.C:
			if err := c.Flush(ctx); err != nil {
				log.Printf("platform: report failed (decisions retained for retry): %v", err)
			}
		}
	}
}

// CheckIn performs one heartbeat/config poll and applies the returned mode.
func (c *Client) CheckIn(ctx context.Context) error {
	const query = `mutation AgentCheckIn($input: ClusterAgentCheckInInput!) {
  clusterAgentCheckIn(input: $input) { clusterID enforcementMode }
}`

	var resp struct {
		ClusterAgentCheckIn struct {
			ClusterID       string `json:"clusterID"`
			EnforcementMode string `json:"enforcementMode"`
		} `json:"clusterAgentCheckIn"`
	}

	err := c.do(ctx, query, map[string]any{"input": map[string]any{
		"clusterUID":   c.cfg.ClusterUID,
		"agentVersion": c.cfg.AgentVersion,
	}}, &resp)
	if err != nil {
		return err
	}

	mode := resp.ClusterAgentCheckIn.EnforcementMode
	c.modeMu.Lock()
	changed := c.mode != mode
	c.mode = mode
	c.modeMu.Unlock()
	if changed {
		log.Printf("platform: enforcement mode is now %s", mode)
	}

	return nil
}

// Flush reports every queued aggregate, in batches of MaxBatch. On failure the
// unsent aggregates are merged back into the queue for the next attempt.
func (c *Client) Flush(ctx context.Context) error {
	c.queueMu.Lock()
	if c.dropped > 0 {
		log.Printf("platform: WARNING dropped %d aggregated decision(s) while the platform was unreachable", c.dropped)
		c.dropped = 0
	}
	pending := make([]*aggregated, 0, len(c.queue))
	for _, agg := range c.queue {
		pending = append(pending, agg)
	}
	c.queue = map[string]*aggregated{}
	c.queueMu.Unlock()

	if len(pending) == 0 {
		return nil
	}

	// Oldest first, so retries drain in arrival order.
	sort.Slice(pending, func(i, j int) bool { return pending[i].firstSeen.Before(pending[j].firstSeen) })

	for start := 0; start < len(pending); start += c.cfg.MaxBatch {
		end := start + c.cfg.MaxBatch
		if end > len(pending) {
			end = len(pending)
		}

		if err := c.report(ctx, pending[start:end]); err != nil {
			for _, agg := range pending[start:] {
				c.requeue(agg)
			}
			return err
		}
	}

	return nil
}

func (c *Client) requeue(agg *aggregated) {
	c.queueMu.Lock()
	defer c.queueMu.Unlock()
	if len(c.queue) >= c.cfg.MaxQueue {
		c.evictOldestLocked()
	}
	key := strings.Join([]string{
		agg.Namespace, agg.WorkloadKind, agg.WorkloadName,
		agg.ImageRef, agg.ImageDigest,
		agg.Verdict, agg.Action, agg.Mode, agg.Reason,
	}, "\x1f")
	if existing, ok := c.queue[key]; ok {
		existing.count += agg.count
		if agg.firstSeen.Before(existing.firstSeen) {
			existing.firstSeen = agg.firstSeen
		}
		if agg.lastSeen.After(existing.lastSeen) {
			existing.lastSeen = agg.lastSeen
		}
		return
	}
	c.queue[key] = agg
}

func (c *Client) report(ctx context.Context, batch []*aggregated) error {
	const query = `mutation ReportAdmissionDecisions($input: ReportAdmissionDecisionsInput!) {
  reportAdmissionDecisions(input: $input) { accepted }
}`

	decisions := make([]map[string]any, 0, len(batch))
	for _, agg := range batch {
		d := map[string]any{
			"namespace":       agg.Namespace,
			"imageRef":        agg.ImageRef,
			"verdict":         agg.Verdict,
			"action":          agg.Action,
			"mode":            agg.Mode,
			"occurrenceCount": agg.count,
			"firstSeenAt":     agg.firstSeen.UTC().Format(time.RFC3339),
			"lastSeenAt":      agg.lastSeen.UTC().Format(time.RFC3339),
		}
		if agg.WorkloadKind != "" {
			d["workloadKind"] = agg.WorkloadKind
		}
		if agg.WorkloadName != "" {
			d["workloadName"] = agg.WorkloadName
		}
		if agg.ImageDigest != "" {
			d["imageDigest"] = agg.ImageDigest
		}
		if agg.ImageID != "" {
			d["imageID"] = agg.ImageID
		}
		if agg.Reason != "" {
			d["reason"] = agg.Reason
		}
		decisions = append(decisions, d)
	}

	var resp struct {
		ReportAdmissionDecisions struct {
			Accepted int `json:"accepted"`
		} `json:"reportAdmissionDecisions"`
	}

	err := c.do(ctx, query, map[string]any{"input": map[string]any{
		"clusterUID": c.cfg.ClusterUID,
		"decisions":  decisions,
	}}, &resp)
	if err != nil {
		return err
	}

	log.Printf("platform: reported %d aggregated decision(s), platform accepted %d", len(decisions), resp.ReportAdmissionDecisions.Accepted)
	return nil
}

// do executes one GraphQL request with the agent credential.
func (c *Client) do(ctx context.Context, query string, variables map[string]any, out any) error {
	body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.graphqlURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("platform: graphql returned %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}

	envelope := struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&envelope); err != nil {
		return fmt.Errorf("platform: failed to parse graphql response: %w", err)
	}

	if len(envelope.Errors) > 0 {
		msgs := make([]string, 0, len(envelope.Errors))
		for _, e := range envelope.Errors {
			msgs = append(msgs, e.Message)
		}
		return fmt.Errorf("platform: graphql error: %s", strings.Join(msgs, "; "))
	}

	if out != nil {
		if err := json.Unmarshal(envelope.Data, out); err != nil {
			return fmt.Errorf("platform: failed to parse graphql data: %w", err)
		}
	}

	return nil
}

// DetectClusterUID reads the kube-system namespace UID — the de-facto stable
// cluster identity — using the pod's own service account, without client-go.
// The agent's ServiceAccount needs `get` on the kube-system namespace (the
// helm chart grants exactly that and nothing more).
func DetectClusterUID(ctx context.Context) (string, error) {
	const (
		tokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" // #nosec G101 -- well-known in-cluster path, not a credential
		caPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	)

	token, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("not running in-cluster (no service account token): %w", err)
	}

	caCert, err := os.ReadFile(caPath)
	if err != nil {
		return "", fmt.Errorf("failed to read in-cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return "", fmt.Errorf("failed to parse in-cluster CA certificate")
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://kubernetes.default.svc/api/v1/namespaces/kube-system", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to query kube-system namespace: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kube-system namespace lookup returned %s (does the ServiceAccount have get on namespaces/kube-system?)", resp.Status)
	}

	ns := struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}{}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ns); err != nil {
		return "", fmt.Errorf("failed to parse kube-system namespace: %w", err)
	}
	if ns.Metadata.UID == "" {
		return "", fmt.Errorf("kube-system namespace has no UID in response")
	}

	return ns.Metadata.UID, nil
}
