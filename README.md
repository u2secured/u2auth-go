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

// Generate a secret + URI for enrollment
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

For an enrolment that has never authenticated, `LastAuthAt` and `LastAuthOutcome` are both `nil` rather than a zero time / empty string. An `EnrolmentEvent`'s `Place` is a coarse, city-level location (never a coordinate) and is `nil` when no fix was captured.

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
