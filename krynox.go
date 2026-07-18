// Package krynox is the official Go server-side SDK for Krynox Captcha.
//
//	client := krynox.New(os.Getenv("KRYNOX_SECRET"))
//	res, err := client.Verify(ctx, token, remoteIP)
//	if err != nil || !res.Success {
//	    http.Error(w, "captcha failed", http.StatusBadRequest)
//	    return
//	}
//	if res.Risk == "high" || contains(res.Reasons, "tor-exit") { /* add friction */ }
package krynox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const defaultEndpoint = "https://api.krynox.net/siteverify"

// Agent is a cryptographically verified AI agent (Web Bot Auth), when forwarded.
type Agent struct {
	Verified    bool   `json:"verified"`
	Name        string `json:"name"`
	Allowlisted bool   `json:"allowlisted"`
}

// Human is a device-attested real human (Private Access Token), when forwarded.
type Human struct {
	Attested bool   `json:"attested"`
	Method   string `json:"method"`
	Issuer   string `json:"issuer"`
}

// Result is the outcome of a verification.
type Result struct {
	Success     bool     `json:"success"`
	Score       float64  `json:"score"`
	Risk        string   `json:"risk"` // "low" | "medium" | "high"
	Hostname    string   `json:"hostname"`
	ChallengeTS string   `json:"challenge_ts"`
	ErrorCodes  []string `json:"error-codes"`
	Reasons     []string `json:"reasons"` // stable reason codes explaining the score
	Agent       *Agent   `json:"agent"`
	Human       *Human   `json:"human"`
}

// Feedback is the outcome of a feedback report.
type Feedback struct {
	OK        bool `json:"ok"`
	Corrected bool `json:"corrected"`
}

// Classification is the outcome of a content classification.
type Classification struct {
	OK             bool     `json:"ok"`
	Score          float64  `json:"score"`
	Classification string   `json:"classification"` // "GOOD" | "SUSPECT" | "BAD"
	Reasons        []string `json:"reasons"`
	Blocked        bool     `json:"blocked"`
	ErrorCodes     []string `json:"error-codes"`
}

// Error codes returned by the API + SDK transport.
const (
	ErrMissingResponse = "missing-input-response"
	ErrInvalidResponse = "invalid-input-response"
	ErrInvalidSecret   = "invalid-input-secret"
	ErrRateLimited     = "rate-limited"
	ErrRequestFailed   = "request-failed"
)

// Client verifies Krynox Captcha solutions.
type Client struct {
	secret   string
	endpoint string
	http     *http.Client
	retries  int
}

// Option configures a Client.
type Option func(*Client)

// WithEndpoint overrides the verify endpoint (self-hosted / staging).
func WithEndpoint(url string) Option { return func(c *Client) { c.endpoint = url } }

// WithHTTPClient supplies a custom *http.Client (timeouts, transport, …).
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithRetries sets the number of transient-failure retries (default 2).
func WithRetries(n int) Option { return func(c *Client) { c.retries = n } }

// New creates a client.
func New(secret string, opts ...Option) *Client {
	c := &Client{secret: secret, endpoint: defaultEndpoint, http: &http.Client{Timeout: 5 * time.Second}, retries: 2}
	for _, o := range opts {
		o(c)
	}
	return c
}

func backoff(attempt int) time.Duration {
	ms := 100 * (1 << uint(attempt))
	if ms > 1000 {
		ms = 1000
	}
	return time.Duration(ms) * time.Millisecond
}

func randomKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (c *Client) derive(path string) string {
	return strings.TrimSuffix(c.endpoint, "/siteverify") + path
}

// postJSON posts payload to url and decodes the response into out, retrying transient failures
// (network error / 429 / 5xx). A fresh request is built each attempt — an http.Request body is
// consumed once, so it cannot be replayed.
func (c *Client) postJSON(ctx context.Context, url string, payload map[string]any, out any) error {
	body, _ := json.Marshal(payload)
	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			if attempt < c.retries {
				time.Sleep(backoff(attempt))
				continue
			}
			return err
		}
		if (resp.StatusCode == 429 || resp.StatusCode >= 500) && attempt < c.retries {
			resp.Body.Close()
			lastErr = errors.New("krynox: transient http status " + resp.Status)
			time.Sleep(backoff(attempt))
			continue
		}
		defer resp.Body.Close()
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return lastErr
}

// Verify checks a captcha response token. remoteIP is optional ("").
func (c *Client) Verify(ctx context.Context, response, remoteIP string) (*Result, error) {
	if c.secret == "" {
		return nil, errors.New("krynox: secret key is required")
	}
	if response == "" {
		return &Result{Success: false, ErrorCodes: []string{ErrMissingResponse}}, nil
	}
	payload := map[string]any{"secret": c.secret, "response": response, "remoteip": remoteIP}
	// A token is single-use, so a retried verify carries an idempotency key — the server returns
	// the first outcome instead of failing the now-consumed token.
	if c.retries > 0 {
		payload["idempotency_key"] = randomKey()
	}
	var out Result
	if err := c.postJSON(ctx, c.endpoint, payload, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Feedback reports detection-quality feedback ("human" | "bot"). Flagging an auto-blocked IP as
// "human" un-blocks it server-side (false-positive correction). ip and note are optional ("").
func (c *Client) Feedback(ctx context.Context, label, ip, note string) (*Feedback, error) {
	if c.secret == "" {
		return nil, errors.New("krynox: secret key is required")
	}
	var out Feedback
	err := c.postJSON(ctx, c.derive("/feedback"), map[string]any{"secret": c.secret, "label": label, "ip": ip, "note": note}, &out)
	return &out, err
}

// Report is a deprecated alias for Feedback, kept for backward compatibility.
//
// Deprecated: use Feedback (naming parity with the other SDKs).
func (c *Client) Report(ctx context.Context, label, ip, note string) (*Feedback, error) {
	return c.Feedback(ctx, label, ip, note)
}

// Classify scores submitted content for spam/abuse. Pass text, or a fields map (or both); ip is
// optional ("").
func (c *Client) Classify(ctx context.Context, text, ip string, fields map[string]any) (*Classification, error) {
	if c.secret == "" {
		return nil, errors.New("krynox: secret key is required")
	}
	payload := map[string]any{"secret": c.secret, "text": text, "ip": ip}
	if fields != nil {
		payload["fields"] = fields
	}
	var out Classification
	err := c.postJSON(ctx, c.derive("/classify"), payload, &out)
	return &out, err
}
