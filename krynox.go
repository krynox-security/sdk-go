// Package krynox is the official Go server-side verification SDK for Krynox Captcha.
//
//	client := krynox.New(os.Getenv("KRYNOX_SECRET"))
//	res, err := client.Verify(ctx, token, remoteIP)
//	if err != nil || !res.Success {
//	    http.Error(w, "captcha failed", http.StatusBadRequest)
//	    return
//	}
//	if res.Risk == "high" { /* add friction */ }
package krynox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

const defaultEndpoint = "https://captcha.krynox.id/siteverify"

// Result is the outcome of a verification.
type Result struct {
	Success     bool     `json:"success"`
	Score       float64  `json:"score"`
	Risk        string   `json:"risk"` // "low" | "medium" | "high"
	Hostname    string   `json:"hostname"`
	ChallengeTS string   `json:"challenge_ts"`
	ErrorCodes  []string `json:"error-codes"`
}

// Client verifies Krynox Captcha solutions.
type Client struct {
	secret   string
	endpoint string
	http     *http.Client
}

// Option configures a Client.
type Option func(*Client)

// WithEndpoint overrides the verify endpoint (self-hosted / staging).
func WithEndpoint(url string) Option { return func(c *Client) { c.endpoint = url } }

// WithHTTPClient supplies a custom *http.Client (timeouts, transport, …).
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// New creates a verification client.
func New(secret string, opts ...Option) *Client {
	c := &Client{secret: secret, endpoint: defaultEndpoint, http: &http.Client{Timeout: 5 * time.Second}}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Verify checks a captcha response token. remoteIP is optional ("").
func (c *Client) Verify(ctx context.Context, response, remoteIP string) (*Result, error) {
	if c.secret == "" {
		return nil, errors.New("krynox: secret key is required")
	}
	if response == "" {
		return &Result{Success: false, ErrorCodes: []string{"missing-input-response"}}, nil
	}

	body, _ := json.Marshal(map[string]string{"secret": c.secret, "response": response, "remoteip": remoteIP})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out Result
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Feedback is the outcome of a feedback report.
type Feedback struct {
	OK        bool `json:"ok"`
	Corrected bool `json:"corrected"`
}

// Report sends detection-quality feedback ("human" | "bot"). Flagging an
// auto-blocked IP as "human" un-blocks it server-side (false-positive
// correction). ip and note are optional ("").
func (c *Client) Report(ctx context.Context, label, ip, note string) (*Feedback, error) {
	if c.secret == "" {
		return nil, errors.New("krynox: secret key is required")
	}

	endpoint := strings.TrimSuffix(c.endpoint, "/siteverify") + "/feedback"
	body, _ := json.Marshal(map[string]string{"secret": c.secret, "label": label, "ip": ip, "note": note})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out Feedback
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}
