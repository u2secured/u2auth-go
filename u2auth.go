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

const defaultBaseURL = "https://app.u2secured.io"

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
	var result PushResult
	if err := c.post("/api/v1/sdk/push/request", body, &result); err != nil {
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
}

// ListEnrolments lists the enrolments for this app. The app is resolved from
// the API key — there is no app id parameter. Limit <= 0 is treated as
// unset and omitted from the query, same as an empty Cursor/Sort/Order.
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
	path := fmt.Sprintf("/api/v1/sdk/enrolments/%s/events", enrolmentID)
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
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("u2auth: marshal request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("u2auth: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
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
