package u2auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const defaultBaseURL = "https://auth.u2secured.com"

// ClientOptions allows customising the U2Auth client.
type ClientOptions struct {
	BaseURL    string
	HTTPClient *http.Client
}

// Client is the U2Auth API client.
type Client struct {
	apiKey     string
	baseURL    string
	httpClient *http.Client
}

// NewClient creates a new Client with the given API key and optional options.
func NewClient(apiKey string, opts *ClientOptions) *Client {
	c := &Client{
		apiKey:  apiKey,
		baseURL: defaultBaseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	if opts != nil {
		if opts.BaseURL != "" {
			c.baseURL = opts.BaseURL
		}
		if opts.HTTPClient != nil {
			c.httpClient = opts.HTTPClient
		}
	}
	return c
}

// APIError represents an error returned by the U2Auth API.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("u2auth: API error %d %s: %s", e.StatusCode, e.Code, e.Message)
}

// VerifyResult is the response from VerifyTOTP.
type VerifyResult struct {
	Valid bool `json:"valid"`
}

// PushResult is the response from RequestPush.
type PushResult struct {
	ApprovalID  string `json:"approval_id"`
	MatchNumber int    `json:"match_number"`
	Status      string `json:"status"`
	ExpiresAt   string `json:"expires_at"`
}

// PushStatus is the response from GetPushStatus.
type PushStatus struct {
	ApprovalID string     `json:"approval_id"`
	Status     string     `json:"status"`
	Reason     string     `json:"reason,omitempty"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// PairingCode is a short-lived code an end user redeems in the U2 Secured app
// to bind a user identifier to their account.
type PairingCode struct {
	Code      string `json:"code"`
	ExpiresAt string `json:"expires_at"`
}

// PushOptions are optional parameters for RequestPush.
type PushOptions struct {
	WebhookURL string `json:"webhook_url,omitempty"`
	TTL        int    `json:"ttl,omitempty"`
	// IdempotencyKey collapses a repeated RequestPush into the ORIGINAL
	// approval instead of sending the user a second notification. It travels
	// as the Idempotency-Key HTTP header, never in the body — hence json:"-".
	//
	// The key must be stable across the retry, so the SDK cannot invent one
	// for you: derive it from whatever identifies the attempt in your system.
	// A nonce rendered into the login form works well, because a double-click
	// and a back-then-resubmit both carry the same one while a fresh page load
	// mints a new one.
	//
	// This is not Stripe-style idempotency: there is no fixed replay window.
	// The server frees the key once the approval is approved, denied or
	// expired, so a genuine retry after that mints a new request rather than
	// replaying the old one. A key held by a live approval for a DIFFERENT
	// request returns *APIError with Code "IDEMPOTENCY_KEY_REUSED"; one longer
	// than 255 characters returns Code "INVALID_IDEMPOTENCY_KEY".
	IdempotencyKey string `json:"-"`
}

// VerifyTOTP verifies a TOTP code against a shared secret.
func (c *Client) VerifyTOTP(secret, code string) (*VerifyResult, error) {
	body := map[string]string{
		"secret": secret,
		"code":   code,
	}
	var result VerifyResult
	if err := c.post("/api/v1/sdk/totp/verify", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RequestPush creates a push approval request.
func (c *Client) RequestPush(userIdentifier, context string, opts *PushOptions) (*PushResult, error) {
	body := map[string]interface{}{
		"user_identifier": userIdentifier,
		"context":         context,
	}
	if opts != nil {
		if opts.WebhookURL != "" {
			body["webhook_url"] = opts.WebhookURL
		}
		if opts.TTL > 0 {
			body["ttl"] = opts.TTL
		}
	}
	var headers map[string]string
	if opts != nil && opts.IdempotencyKey != "" {
		headers = map[string]string{"Idempotency-Key": opts.IdempotencyKey}
	}

	var result PushResult
	if err := c.postWithHeaders("/api/v1/sdk/push/request", body, headers, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetPushStatus retrieves the status of a push approval request.
func (c *Client) GetPushStatus(approvalID string) (*PushStatus, error) {
	var result PushStatus
	if err := c.get(fmt.Sprintf("/api/v1/sdk/push/%s/status", approvalID), &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// CreatePairingCode mints a pairing code binding userIdentifier — your own
// opaque id for the user — to whichever account redeems it in the U2 Secured
// app. Pass the same string to RequestPush afterwards.
func (c *Client) CreatePairingCode(userIdentifier string) (*PairingCode, error) {
	body := map[string]string{"user_identifier": userIdentifier}
	var result PairingCode
	if err := c.post("/api/v1/sdk/pairing-codes", body, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DeleteEnrolment removes the link between this app and userIdentifier.
// Returns an *APIError with Code "ENROLMENT_NOT_FOUND" if there was none.
func (c *Client) DeleteEnrolment(userIdentifier string) error {
	q := url.Values{"user_identifier": {userIdentifier}}
	return c.delete("/api/v1/sdk/enrolments?" + q.Encode())
}

// Place is a coarse, city-level location for an authentication event. It is
// derived from IP geolocation and is never a precise coordinate.
type Place struct {
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
}

// Enrolment is the link between this app and one end user, identified by the
// user_identifier passed to CreatePairingCode / RequestPush. LastAuthAt and
// LastAuthOutcome are both nil when the enrolment has never authenticated —
// distinct from a zero time or an empty string.
type Enrolment struct {
	ID              string     `json:"id"`
	UserIdentifier  string     `json:"user_identifier"`
	CreatedAt       time.Time  `json:"created_at"`
	LastAuthAt      *time.Time `json:"last_auth_at"`
	LastAuthOutcome *string    `json:"last_auth_outcome"`
	PushReady       bool       `json:"push_ready"`
}

// PairingCodeStatus is where a pairing code sits in its lifecycle. A code that
// never existed and one belonging to another app both report "expired":
// distinguishing them would make the endpoint a probing oracle.
type PairingCodeStatus struct {
	Status      string `json:"status"`
	EnrolmentID string `json:"enrolment_id,omitempty"`
}

// EnrolmentEvent is a single authentication attempt recorded against an
// enrolment.
type EnrolmentEvent struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Outcome   string    `json:"outcome"`
	CreatedAt time.Time `json:"created_at"`
	// Place is a coarse, city-level location — never a coordinate — or nil
	// when no location fix was captured for this event.
	Place      *Place `json:"place"`
	NewCountry bool   `json:"new_country"`
}

// EnrolmentPage is one page of ListEnrolments results.
type EnrolmentPage struct {
	Items      []Enrolment `json:"items"`
	NextCursor string      `json:"next_cursor"`
}

// EnrolmentEventPage is one page of ListEnrolmentEvents results.
type EnrolmentEventPage struct {
	Items      []EnrolmentEvent `json:"items"`
	NextCursor string           `json:"next_cursor"`
}

// ListEnrolmentsOptions are optional parameters for ListEnrolments. Cursor is
// opaque and bound to the Sort/Order that minted it — pass it back verbatim
// on the next call; replaying it under a different Sort/Order is rejected.
type ListEnrolmentsOptions struct {
	Limit  int
	Cursor string
	Sort   string // "created_at" | "user_identifier" | "last_auth_at"
	Order  string // "asc" | "desc"
	// UserIdentifier filters to one developer-chosen identifier. Unlike
	// Cursor/Sort/Order it is an arbitrary caller string rather than an
	// opaque token or a fixed enum, so an empty string is the only value
	// treated as unset — there is no equivalent of PHP's empty() trap in Go,
	// so a plain != "" check is all that is needed.
	UserIdentifier string
}

// ListEnrolments lists the enrolments for this app. The app is resolved from
// the API key — there is no app id parameter. Limit <= 0 is treated as
// unset and omitted from the query, same as an empty Cursor/Sort/Order/
// UserIdentifier.
// Returns an *APIError with Code "INVALID_LIMIT" if Limit is outside 1..100,
// "INVALID_SORT" for an unrecognised Sort, or "INVALID_CURSOR" if Cursor was
// minted under a different Sort/Order.
func (c *Client) ListEnrolments(opts *ListEnrolmentsOptions) (*EnrolmentPage, error) {
	q := url.Values{}
	if opts != nil {
		if opts.Limit > 0 {
			q.Set("limit", strconv.Itoa(opts.Limit))
		}
		if opts.Cursor != "" {
			q.Set("cursor", opts.Cursor)
		}
		if opts.Sort != "" {
			q.Set("sort", opts.Sort)
		}
		if opts.Order != "" {
			q.Set("order", opts.Order)
		}
		if opts.UserIdentifier != "" {
			q.Set("user_identifier", opts.UserIdentifier)
		}
	}
	path := "/api/v1/sdk/enrolments"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var result EnrolmentPage
	if err := c.get(path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetEnrolment looks up this app's enrolment for one user identifier.
//
// Returns (nil, nil) when the user is not linked. That is deliberately not an
// error: at login "not linked" is the normal answer, and making callers
// inspect an error on the common path is how integrations end up swallowing
// real ones too.
func (c *Client) GetEnrolment(userIdentifier string) (*Enrolment, error) {
	page, err := c.ListEnrolments(&ListEnrolmentsOptions{
		UserIdentifier: userIdentifier,
		Limit:          1,
	})
	if err != nil {
		return nil, err
	}
	if len(page.Items) == 0 {
		return nil, nil
	}
	return &page.Items[0], nil
}

// GetPairingCodeStatus reads where a pairing code is in its lifecycle:
// pending, redeemed or expired. A code that never existed and one belonging
// to another app both read as expired.
func (c *Client) GetPairingCodeStatus(code string) (*PairingCodeStatus, error) {
	var out PairingCodeStatus
	if err := c.get("/api/v1/sdk/pairing-codes/"+url.PathEscape(code), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListEnrolmentEvents lists the authentication events for one enrolment.
// Cursor is opaque; pass it back verbatim on the next call to page. Limit
// <= 0 is treated as unset and omitted from the query, same as an empty
// Cursor.
// Returns an *APIError with Code "ENROLMENT_NOT_FOUND" if there is no such
// enrolment, "INVALID_LIMIT" if Limit is outside 1..100, or "INVALID_CURSOR"
// if Cursor is malformed or was minted for a different enrolment.
func (c *Client) ListEnrolmentEvents(enrolmentID string, limit int, cursor string) (*EnrolmentEventPage, error) {
	q := url.Values{}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	// PathEscape, matching GetPairingCodeStatus: an enrolment id is a server
	// -minted opaque string, but it is interpolated into a path segment, so
	// escape it rather than trusting its shape.
	path := "/api/v1/sdk/enrolments/" + url.PathEscape(enrolmentID) + "/events"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var result EnrolmentEventPage
	if err := c.get(path, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) post(path string, body interface{}, out interface{}) error {
	return c.postWithHeaders(path, body, nil, out)
}

// postWithHeaders is post plus caller-supplied headers. An empty value is
// skipped rather than sent blank: the server distinguishes a present-but-empty
// Idempotency-Key from an absent one.
func (c *Client) postWithHeaders(path string, body interface{}, headers map[string]string, out interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("u2auth: marshal request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("u2auth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	return c.do(req, out)
}

func (c *Client) get(path string, out interface{}) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("u2auth: build request: %w", err)
	}
	return c.do(req, out)
}

// delete issues a DELETE and discards the body. Endpoints answering 204 carry
// no payload, which do() tolerates because out is nil.
func (c *Client) delete(path string) error {
	req, err := http.NewRequest(http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("u2auth: build request: %w", err)
	}
	return c.do(req, nil)
}

func (c *Client) do(req *http.Request, out interface{}) error {
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("u2auth: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("u2auth: read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		_ = json.Unmarshal(respBody, &errResp)
		return &APIError{
			StatusCode: resp.StatusCode,
			Code:       errResp.Error.Code,
			Message:    errResp.Error.Message,
		}
	}

	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("u2auth: decode response: %w", err)
		}
	}
	return nil
}
