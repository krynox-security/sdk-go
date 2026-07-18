# krynox-go

Official Go server-side verification SDK for **Krynox Captcha**.

```bash
go get github.com/krynox-security/sdk-go
```

```go
import krynox "github.com/krynox-security/sdk-go"

client := krynox.New(os.Getenv("KRYNOX_SECRET"))

res, err := client.Verify(r.Context(), r.FormValue("krynox-captcha"), r.RemoteAddr)
if err != nil || !res.Success {
    http.Error(w, "captcha failed", http.StatusBadRequest)
    return
}
if res.Risk == "high" || contains(res.Reasons, "tor-exit") {
    // add friction
}
```

### Reasons, agents & attested humans

- `res.Reasons` — stable codes explaining the score (`"tor-exit"`, `"elevated-request-rate"`, …).
- `res.Agent` — non-nil when a **verified AI agent** (Web Bot Auth) was forwarded:
  `{ Verified, Name, Allowlisted }`. Allowlist good bots instead of blocking them.
- `res.Human` — non-nil when a **device-attested human** (Private Access Token) was forwarded:
  `{ Attested, Method, Issuer }`.

```go
if res.Agent != nil && res.Agent.Verified && res.Agent.Allowlisted { /* trusted crawler */ }
if res.Human != nil && res.Human.Attested { /* proven human, skip friction */ }
```

### Content classification (spam/abuse)

```go
c, _ := client.Classify(ctx, comment, r.RemoteAddr, nil) // or pass a fields map
if c.Blocked || c.Classification == "BAD" {
    http.Error(w, "rejected", http.StatusBadRequest)
}
```

### Reliability

Transient failures (network, `429`, `5xx`) are retried automatically (default **2**, exponential
backoff; tune with `WithRetries(n)`). A retried `Verify` carries an **idempotency key** so it never
fails the single-use token — the server replays the first outcome.

### Feedback (false-positive correction)

Report detection quality back to Krynox. Flagging an auto-blocked IP as `"human"`
immediately un-blocks it server-side — a closed feedback loop that tunes detection.

```go
// a real user got blocked by mistake → un-block their IP
fb, err := client.Feedback(r.Context(), "human", r.RemoteAddr, "support ticket #1234")
if err == nil && fb.Corrected {
    // IP was un-blocked
}

// confirm a bot you let through
client.Feedback(r.Context(), "bot", suspiciousIP, "")
```

### API
- `krynox.New(secret, ...Option)` — options: `WithEndpoint(url)`, `WithHTTPClient(h)`, `WithRetries(n)`
- `(*Client).Verify(ctx, response, remoteIP) (*Result, error)`
- `(*Client).Classify(ctx, text, ip, fields) (*Classification, error)`
- `(*Client).Feedback(ctx, label, ip, note) (*Feedback, error)` — `label` is `"human"` or `"bot"`
  (`Report` remains as a deprecated alias)

`Result`: `Success, Score, Risk, Hostname, ChallengeTS, ErrorCodes, Reasons, Agent, Human`.
`Classification`: `OK, Score, Classification, Reasons, Blocked, ErrorCodes`.
`Feedback`: `OK, Corrected`. Error codes: `krynox.ErrMissingResponse`, `krynox.ErrRateLimited`, ….
