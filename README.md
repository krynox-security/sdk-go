# krynox-go

Official Go server-side verification SDK for **Krynox Captcha**.

```bash
go get gitlab.com/krynox/captcha/sdk-go
```

```go
import krynox "gitlab.com/krynox/captcha/sdk-go"

client := krynox.New(os.Getenv("KRYNOX_SECRET"))

res, err := client.Verify(r.Context(), r.FormValue("krynox-captcha"), r.RemoteAddr)
if err != nil || !res.Success {
    http.Error(w, "captcha failed", http.StatusBadRequest)
    return
}
if res.Risk == "high" {
    // add friction
}
```

### Feedback (false-positive correction)

Report detection quality back to Krynox. Flagging an auto-blocked IP as `"human"`
immediately un-blocks it server-side — a closed feedback loop that tunes detection.

```go
// a real user got blocked by mistake → un-block their IP
fb, err := client.Report(r.Context(), "human", r.RemoteAddr, "support ticket #1234")
if err == nil && fb.Corrected {
    // IP was un-blocked
}

// confirm a bot you let through
client.Report(r.Context(), "bot", suspiciousIP, "")
```

### API
- `krynox.New(secret, ...Option)` — options: `WithEndpoint(url)`, `WithHTTPClient(h)`
- `(*Client).Verify(ctx, response, remoteIP) (*Result, error)`
- `(*Client).Report(ctx, label, ip, note) (*Feedback, error)` — `label` is `"human"` or `"bot"`

`Result`: `Success, Score, Risk, Hostname, ChallengeTS, ErrorCodes`.
`Feedback`: `OK, Corrected`.
