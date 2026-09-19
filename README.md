# u2auth-go

Go SDK for the U2Auth platform — TOTP verification, push approvals, and local TOTP helpers.

## Install

```bash
go get github.com/u2secured/u2auth-go
```

## Quick Start

```go
client := u2auth.NewClient("rka_your_api_key", nil)

// Verify a TOTP code
result, err := client.VerifyTOTP("BASE32SECRET", "123456")

// Request push approval
push, err := client.RequestPush("user@example.com", "Login from Chrome", nil)

// Poll status
status, err := client.GetPushStatus(push.ApprovalID)

// Generate a secret + URI for enrolment
secret, _ := u2auth.GenerateSecret(20)
uri := u2auth.GenerateQRCodeURI("MyApp", "user@example.com", secret, nil)
```

## API Reference

### Client

```go
func NewClient(apiKey string, opts *ClientOptions) *Client
```

`ClientOptions`:
- `BaseURL string` — override API base URL (default: `https://app.u2secured.io`)
- `HTTPClient *http.Client` — custom HTTP client

### VerifyTOTP

```go
func (c *Client) VerifyTOTP(secret, code string) (*VerifyResult, error)
```

Calls `POST /api/v1/sdk/totp/verify`. Returns `VerifyResult{Valid bool}`.

### RequestPush

```go
func (c *Client) RequestPush(userIdentifier, context string, opts *PushOptions) (*PushResult, error)
```

Calls `POST /api/v1/sdk/push/request`. `PushOptions` fields: `WebhookURL`, `TTL` (seconds), `IdempotencyKey`.
Returns `PushResult{ApprovalID, Status, ExpiresAt}`.

`userIdentifier` matching is case-sensitive and otherwise unnormalised — it's your own key into
your system, not ours, so folding case could silently merge two genuinely different users. Pass
the exact same string here as the one given to `CreatePairingCode`. A mismatch (most often a
casing difference) returns an `*APIError` with Code `"ENROLMENT_NOT_FOUND"` — no enrolment at all
for that identifier — which is distinct from `"NO_DEVICE"` (enrolled, but no confirmed device yet).

### GetPushStatus

```go
func (c *Client) GetPushStatus(approvalID string) (*PushStatus, error)
```

Calls `GET /api/v1/sdk/push/{id}/status`. Returns `PushStatus{ApprovalID, Status}`.

### Helpers (no API call)

```go
func GenerateSecret(byteLen int) (string, error)
func GenerateQRCodeURI(issuer, account, secret string, opts *QRCodeOptions) string
func GenerateRecoveryCodes(count int) ([]string, error)
```

`QRCodeOptions` fields: `Algorithm` (default SHA1), `Digits` (default 6), `Period` (default 30).

### Enrolments

```go
func (c *Client) ListEnrolments(opts *ListEnrolmentsOptions) (*EnrolmentPage, error)
func (c *Client) ListEnrolmentEvents(enrolmentID string, limit int, cursor string) (*EnrolmentEventPage, error)
```

Calls `GET /api/v1/sdk/enrolments` and `GET /api/v1/sdk/enrolments/{enrolmentId}/events`. The app is resolved from the API key — there is no `app_id` parameter.

`ListEnrolmentsOptions` fields: `Limit`, `Cursor`, `Sort` (`"created_at"` | `"user_identifier"` | `"last_auth_at"`), `Order` (`"asc"` | `"desc"`). `Limit` (also the plain `limit int` parameter on `ListEnrolmentEvents`) `<= 0` is treated as unset and omitted from the query, same as an empty `Cursor`/`Sort`/`Order`; a value outside `1..100` returns an `*APIError` with Code `"INVALID_LIMIT"`. A page's `NextCursor` is opaque and bound to the `Sort`/`Order` that minted it — pass it back verbatim; replaying it under a different `Sort`/`Order` returns an `*APIError` with Code `"INVALID_CURSOR"`.

For an enrolment that has never authenticated, `LastAuthAt` and `LastAuthOutcome` are both `nil` rather than a zero time / empty string. An `EnrolmentEvent`'s `Place` is a coarse, city-level location (never a coordinate) and is `nil` when no fix was captured. `Enrolment.PushReady` reports whether the linked device can currently receive a push (a confirmed device is enrolled) — check it before calling `RequestPush` if you want to route a not-ready user to a different second factor instead.

`ListEnrolmentsOptions` also takes `UserIdentifier` to filter to one developer-chosen identifier. It is an arbitrary caller string, not an opaque token like `Cursor` or a fixed enum like `Sort`/`Order`, so it is included whenever non-empty — there is no reserved "unset" value to trip over.

```go
cursor := ""
for {
    page, err := client.ListEnrolments(&u2auth.ListEnrolmentsOptions{Limit: 50, Cursor: cursor})
    if err != nil { return err }
    for _, e := range page.Items { fmt.Println(e.UserIdentifier, e.LastAuthAt) }
    if page.NextCursor == "" { break }
    cursor = page.NextCursor
}
```

### Linked approvals

"Linked approvals" is link-then-push: a user links their phone to *your* account once (via a
pairing code), and afterwards you call `RequestPush` directly against their `userIdentifier` — no
code re-entry required.

```go
// 1. Mint a code and show it to the signed-in user (e.g. as text + a QR code).
pairing, err := client.CreatePairingCode("user@example.com")
// pairing.Code == "af17-b500", pairing.ExpiresAt == "2026-09-15T10:10:00Z"

// 2. The user opens the U2 Secured app and redeems the code there. Poll its
//    status from wherever the user is waiting (e.g. the browser via your own
//    endpoint) — see the WaitForLink warning below before calling it from a
//    request a user's browser is blocked on.
status, err := client.GetPairingCodeStatus(pairing.Code)
// status.Status is "pending" | "redeemed" | "expired"; status.EnrolmentID is
// set once redeemed.

// 3. Once redeemed, the identifier is linked. From then on, request push
//    directly — no pairing code involved.
push, err := client.RequestPush("user@example.com", "Login from Chrome", nil)
```

#### GetEnrolment

```go
func (c *Client) GetEnrolment(userIdentifier string) (*Enrolment, error)
```

Looks up this app's enrolment for one user identifier. **Returns `(nil, nil)` when the user is not
linked — it never returns an error for that case.** At login, "this user has not linked a phone" is
the normal answer, not an error; forcing every caller to branch on an error for the common path is
how integrations end up swallowing real errors too. This is deliberately unlike `DeleteEnrolment`,
where the absence genuinely is the anomaly and it returns `*APIError` with Code
`"ENROLMENT_NOT_FOUND"`.

```go
enrolment, err := client.GetEnrolment("user@example.com")
if err != nil {
    return err
}
if enrolment == nil {
    // show a "link your phone" prompt
} else if enrolment.PushReady {
    push, err := client.RequestPush("user@example.com", "Login from Chrome", nil)
}
```

#### GetPairingCodeStatus

```go
func (c *Client) GetPairingCodeStatus(code string) (*PairingCodeStatus, error)
```

Calls `GET /api/v1/sdk/pairing-codes/{code}`. Returns `PairingCodeStatus{Status, EnrolmentID}`,
where `Status` is `"pending"`, `"redeemed"` or `"expired"`. A code that never existed, and one
belonging to another app, both read as `"expired"` — distinguishing them would make the endpoint a
probing oracle. This is the call to poll from wherever the user is waiting.

#### WaitForLink

```go
func (c *Client) WaitForLink(ctx context.Context, code string, opts *WaitForLinkOptions) (*Enrolment, error)
```

Blocking convenience helper that mirrors `WaitForApproval` — same options shape, same polling
structure — so a developer who has used one can use the other without re-reading the docs. Polls
`GetPairingCodeStatus` until the code is redeemed, then fetches and returns the resulting
**enrolment** (not just the status — that's why `UserIdentifier` is required: the status response
alone doesn't carry enough to look the enrolment up).

`WaitForLinkOptions` fields:

| field | type | default | notes |
|---|---|---|---|
| `UserIdentifier` | `string` | — | **Required.** The identifier the code was minted for. Returns `*APIError` with Code `"MISSING_USER_IDENTIFIER"` if empty — never silently ignored. |
| `Interval` | `time.Duration` | `2s` | Poll interval. Zero or negative takes the default. |
| `Timeout` | `time.Duration` | `2m` | Give up after this long. Zero or negative takes the default. |

Returns `*APIError` with Code `"PAIRING_CODE_EXPIRED"` if the code lapses before redemption,
`"LINK_TIMEOUT"` if the deadline passes while it's still pending, or `"ENROLMENT_NOT_FOUND"` if the
code comes back redeemed but no matching enrolment can be found for `UserIdentifier` — rare but
reachable, since redemption and the enrolment lookup are two separate backend calls. Cancelling
`ctx` returns `ctx.Err()`.

```go
enrolment, err := client.WaitForLink(ctx, pairing.Code, &u2auth.WaitForLinkOptions{
    UserIdentifier: "user@example.com",
})
```

> **This blocks the calling goroutine, exactly like `WaitForApproval`.** Never call it from an HTTP
> handler a user's browser is waiting on — a normal request has nowhere near a 2-minute budget, and
> tying up a handler goroutine for the whole poll will exhaust your server under modest traffic.
> Reach for `WaitForLink` only from something that already owns a long-lived context (a CLI, a
> background job, a queue worker); poll `GetPairingCodeStatus` from the browser on an interval
> instead for anything request-driven.

### Error Handling

API errors return `*APIError` with `StatusCode`, `Code`, and `Message` fields.

Pass the idempotency option to suppress duplicate requests. While the approval is
still pending, repeating the call with the same key returns the original — same
`ApprovalID`, same `MatchNumber`, and no second notification:

```go
push, err := client.RequestPush("user@example.com", "Login from Chrome",
    &u2auth.PushOptions{IdempotencyKey: formNonce})
```

The key frees itself once the approval is approved, denied or expired, so a
genuine retry after that mints a new request. This is **not** Stripe-style
idempotency: there is no fixed replay window and no stored-response replay.

The key must be stable across the retry, so the SDK cannot invent one for you: a
key minted inside the call is a new key every call and protects nothing. Mint a
nonce when the login form is rendered and carry it in a hidden field — a
double-click and a back-then-resubmit both send the same one, while a fresh page
load mints a new one.

Reusing a live key for a different request raises `*APIError` with code `IDEMPOTENCY_KEY_REUSED`; a key over
255 characters raises `INVALID_IDEMPOTENCY_KEY`.

## Verifying webhooks

```go
event, err := u2auth.VerifyWebhook(rawBody, r.Header.Get("X-U2Auth-Signature"), webhookSecret)
if err != nil {
    // reject: invalid signature or stale timestamp
}
// event.ApprovalID, event.Status ("approved"/"denied"/"expired"), event.Reason
```

Pass the **raw request body bytes** — not a re-serialized struct. Handlers should be idempotent (dedupe on `event.ApprovalID`).

## Waiting for an approval

```go
status, err := client.WaitForApproval(ctx, approvalID, nil) // polls until resolved (default 2s/120s)
if err == u2auth.ErrWaitTimeout {
    // still pending after the timeout
}
```
