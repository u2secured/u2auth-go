package u2auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestClient(server *httptest.Server) *Client {
	return NewClient("rka_testkey", &ClientOptions{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	})
}

func TestVerifyTOTP_Valid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/api/v1/sdk/totp/verify" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer rka_testkey" {
			t.Errorf("missing auth header")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"valid": true})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	res, err := c.VerifyTOTP("JBSWY3DPEHPK3PXP", "123456")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.Valid {
		t.Error("expected valid=true")
	}
}

func TestVerifyTOTP_Invalid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]bool{"valid": false})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	res, err := c.VerifyTOTP("JBSWY3DPEHPK3PXP", "000000")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Valid {
		t.Error("expected valid=false")
	}
}

func TestVerifyTOTP_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]string{
				"code":    "UNAUTHORIZED",
				"message": "invalid api key",
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := c.VerifyTOTP("SECRET", "123456")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", apiErr.StatusCode)
	}
	if apiErr.Code != "UNAUTHORIZED" {
		t.Errorf("expected code UNAUTHORIZED, got %s", apiErr.Code)
	}
}

func TestRequestPush(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sdk/push/request" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{
			"approval_id": "apr_abc123",
			"status":      "pending",
			"expires_at":  "2026-06-01T12:00:00Z",
		})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	res, err := c.RequestPush("user@example.com", "Login from Chrome on macOS", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.ApprovalID != "apr_abc123" {
		t.Errorf("expected approval_id apr_abc123, got %s", res.ApprovalID)
	}
	if res.Status != "pending" {
		t.Errorf("expected status pending, got %s", res.Status)
	}
}

func TestRequestPush_WithOptions(t *testing.T) {
	var receivedBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"approval_id": "apr_xyz",
			"status":      "pending",
			"expires_at":  "2026-06-01T12:00:00Z",
		})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := c.RequestPush("user@example.com", "Test login", &PushOptions{
		WebhookURL: "https://example.com/hook",
		TTL:        300,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedBody["webhook_url"] != "https://example.com/hook" {
		t.Errorf("webhook_url not forwarded: %v", receivedBody)
	}
}

func TestGetPushStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sdk/push/apr_abc123/status" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"approval_id": "apr_abc123",
			"status":      "approved",
		})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	status, err := c.GetPushStatus("apr_abc123")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if status.Status != "approved" {
		t.Errorf("expected status approved, got %s", status.Status)
	}
	if status.ApprovalID != "apr_abc123" {
		t.Errorf("expected approval_id apr_abc123, got %s", status.ApprovalID)
	}
}

func TestGetPushStatus_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": map[string]string{
				"code":    "NOT_FOUND",
				"message": "approval not found",
			},
		})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := c.GetPushStatus("nonexistent")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.Code != "NOT_FOUND" {
		t.Errorf("expected NOT_FOUND, got %s", apiErr.Code)
	}
}

func TestRequestPush_ParsesMatchNumber(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"approval_id":"ap1","match_number":42,"status":"pending","expires_at":"2026-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()
	c := NewClient("k", &ClientOptions{BaseURL: srv.URL})
	res, err := c.RequestPush("user@x", "ctx", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if res.MatchNumber != 42 {
		t.Fatalf("match_number = %d, want 42", res.MatchNumber)
	}
}

func TestGetPushStatus_ParsesReasonAndResolvedAt(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"approval_id":"ap1","status":"denied","reason":"wrong_number","resolved_at":"2026-01-01T00:00:00Z"}`))
	}))
	defer srv.Close()
	c := NewClient("k", &ClientOptions{BaseURL: srv.URL})
	st, err := c.GetPushStatus("ap1")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Reason != "wrong_number" || st.ResolvedAt == nil {
		t.Fatalf("got reason=%q resolvedAt=%v", st.Reason, st.ResolvedAt)
	}
}

func TestCreatePairingCode(t *testing.T) {
	var gotBody map[string]string
	var gotPath, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"code":"3f9a-c210","expires_at":"2026-07-31T10:20:00Z"}`))
	}))
	defer srv.Close()

	res, err := newTestClient(srv).CreatePairingCode("alice@acme.com")
	if err != nil {
		t.Fatalf("CreatePairingCode: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/sdk/pairing-codes" {
		t.Fatalf("wrong request: %s %s", gotMethod, gotPath)
	}
	if gotBody["user_identifier"] != "alice@acme.com" {
		t.Fatalf("body: got %v", gotBody)
	}
	if res.Code != "3f9a-c210" || res.ExpiresAt != "2026-07-31T10:20:00Z" {
		t.Fatalf("result: got %+v", res)
	}
}

func TestDeleteEnrolment(t *testing.T) {
	var gotQuery, gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery, gotMethod = r.URL.RawQuery, r.Method
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	if err := newTestClient(srv).DeleteEnrolment("alice+tag@acme.com"); err != nil {
		t.Fatalf("DeleteEnrolment: %v", err)
	}
	if gotMethod != http.MethodDelete {
		t.Fatalf("method: got %s", gotMethod)
	}
	// "+" must be percent-encoded, not left to mean a space.
	if gotQuery != "user_identifier=alice%2Btag%40acme.com" {
		t.Fatalf("query: got %q", gotQuery)
	}
}

func TestDeleteEnrolment_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"ENROLMENT_NOT_FOUND","message":"no enrolment"}}`))
	}))
	defer srv.Close()

	err := newTestClient(srv).DeleteEnrolment("ghost@acme.com")
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("want *APIError, got %v", err)
	}
	if apiErr.Code != "ENROLMENT_NOT_FOUND" || apiErr.StatusCode != 404 {
		t.Fatalf("want 404/ENROLMENT_NOT_FOUND, got %d/%s", apiErr.StatusCode, apiErr.Code)
	}
}

func TestListEnrolments(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sdk/enrolments" {
			t.Errorf("path = %q", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("limit") != "2" || q.Get("sort") != "last_auth_at" || q.Get("order") != "asc" {
			t.Errorf("query = %v", q)
		}
		// An app id must never be sent — the key identifies the app.
		if q.Get("app_id") != "" {
			t.Errorf("app_id must not be sent, got %q", q.Get("app_id"))
		}
		// Cursor was left unset — it must be genuinely absent from the
		// query, not sent as an empty value, so the request carries only
		// what the caller asked for.
		if q.Has("cursor") {
			t.Errorf("cursor must be omitted when unset, got %q", q.Get("cursor"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"id":"e1","user_identifier":"ellis@acme.test","created_at":"2026-08-01T10:00:00Z","last_auth_at":null,"last_auth_outcome":null}],"next_cursor":"abc"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	page, err := c.ListEnrolments(&ListEnrolmentsOptions{Limit: 2, Sort: "last_auth_at", Order: "asc"})
	if err != nil {
		t.Fatalf("ListEnrolments: %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].UserIdentifier != "ellis@acme.test" {
		t.Errorf("items = %+v", page.Items)
	}
	if page.Items[0].LastAuthAt != nil {
		t.Error("a never-authenticated enrolment must decode as a nil LastAuthAt, not a zero time")
	}
	if page.Items[0].LastAuthOutcome != nil {
		t.Error("a never-authenticated enrolment must decode as a nil LastAuthOutcome, not an empty string")
	}
	if page.NextCursor != "abc" {
		t.Errorf("next_cursor = %q", page.NextCursor)
	}
}

func TestListEnrolments_EmptyOptionsOmitsOptionalParams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		// The common caller shape — no options set at all — must not put
		// sort, order or cursor on the wire, even as empty strings.
		for _, key := range []string{"sort", "order", "cursor"} {
			if q.Has(key) {
				t.Errorf("%s must be omitted when unset, got %q", key, q.Get(key))
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"next_cursor":""}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if _, err := c.ListEnrolments(&ListEnrolmentsOptions{}); err != nil {
		t.Fatalf("ListEnrolments: %v", err)
	}
}

// Contract behaviour: Limit <= 0 is treated as unset and omitted from the
// query, same as Node (client.test.ts) and Python (test_client.py) pin for
// their own SDKs. Zero and negative are pinned as two separate cases — they
// reach "omitted" for different reasons in a reader's head (zero is the Go
// zero value / "never set"; negative is an explicit but out-of-range value)
// even though the code path is one `> 0` check either way.
func TestListEnrolments_ZeroLimitOmitsLimitFromQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("limit") {
			t.Errorf("limit must be omitted when Limit is 0, got %q", r.URL.Query().Get("limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"next_cursor":""}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if _, err := c.ListEnrolments(&ListEnrolmentsOptions{Limit: 0}); err != nil {
		t.Fatalf("ListEnrolments: %v", err)
	}
}

func TestListEnrolments_NegativeLimitOmitsLimitFromQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("limit") {
			t.Errorf("limit must be omitted when Limit is negative, got %q", r.URL.Query().Get("limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"next_cursor":""}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if _, err := c.ListEnrolments(&ListEnrolmentsOptions{Limit: -1}); err != nil {
		t.Fatalf("ListEnrolments: %v", err)
	}
}

func TestListEnrolmentEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sdk/enrolments/e1/events" {
			t.Errorf("path = %q", r.URL.Path)
		}
		q := r.URL.Query()
		if q.Get("limit") != "10" {
			t.Errorf("limit = %q, want 10", q.Get("limit"))
		}
		// cursor was passed as "" — it must be genuinely absent, not sent
		// as an empty value, so the request carries only what the caller
		// asked for.
		if q.Has("cursor") {
			t.Errorf("cursor must be omitted when passed \"\", got %q", q.Get("cursor"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"id":"a1","kind":"push","outcome":"approved","created_at":"2026-08-01T10:00:00Z","place":{"city":"Manchester","region":"England","country":"GB"},"new_country":false},{"id":"a2","kind":"totp","outcome":"verified","created_at":"2026-08-01T09:00:00Z","place":null,"new_country":false}],"next_cursor":""}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	page, err := c.ListEnrolmentEvents("e1", 10, "")
	if err != nil {
		t.Fatalf("ListEnrolmentEvents: %v", err)
	}
	if page.Items[0].Place == nil || page.Items[0].Place.City != "Manchester" {
		t.Errorf("place = %+v", page.Items[0].Place)
	}
	// An event with no fix must be a nil Place, not an empty struct — callers
	// need to tell "unknown" from a blank city.
	if page.Items[1].Place != nil {
		t.Errorf("event without a fix: place = %+v, want nil", page.Items[1].Place)
	}
}

// ListEnrolmentEvents has its own `limit > 0` guard (u2auth.go), separate from
// ListEnrolments', and until now nothing exercised the omission path for it at
// all — TestListEnrolmentEvents above only ever passes limit=10. Zero and
// negative are pinned as two cases for the same reason as on ListEnrolments:
// they reach "omitted" for different reasons in a reader's head, and a
// zero-only test would still pass against a guard written `if limit != 0`,
// which would send -1.
func TestListEnrolmentEvents_ZeroLimitOmitsLimitFromQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("limit") {
			t.Errorf("limit must be omitted when limit is 0, got %q", r.URL.Query().Get("limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"next_cursor":""}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if _, err := c.ListEnrolmentEvents("e1", 0, ""); err != nil {
		t.Fatalf("ListEnrolmentEvents: %v", err)
	}
}

func TestListEnrolmentEvents_NegativeLimitOmitsLimitFromQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("limit") {
			t.Errorf("limit must be omitted when limit is negative, got %q", r.URL.Query().Get("limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"next_cursor":""}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if _, err := c.ListEnrolmentEvents("e1", -1, ""); err != nil {
		t.Fatalf("ListEnrolmentEvents: %v", err)
	}
}

// The enrolment id lands in a URL path segment, so it must be escaped there —
// the same way GetPairingCodeStatus already escapes the pairing code with
// url.PathEscape. Before this was fixed the id was interpolated raw, so an id
// carrying a space or a slash produced a different request target than the
// caller asked for (a slash silently splits the segment and reaches another
// resource entirely). RequestURI is read rather than URL.Path because the
// latter is already percent-decoded and would hide the bug.
func TestListEnrolmentEvents_EscapesEnrolmentIDInPath(t *testing.T) {
	var gotRequestURI string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRequestURI = r.RequestURI
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"next_cursor":""}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if _, err := c.ListEnrolmentEvents("en 1/2", 0, ""); err != nil {
		t.Fatalf("ListEnrolmentEvents: %v", err)
	}

	want := "/api/v1/sdk/enrolments/en%201%2F2/events"
	if gotRequestURI != want {
		t.Errorf("request target = %q, want %q", gotRequestURI, want)
	}
}

// The Idempotency-Key is an HTTP HEADER, not a body field. A key that leaks
// into the JSON body is silently ignored by the server — the retry it was meant
// to collapse sends the user a second push, and nothing fails loudly.
func TestRequestPush_IdempotencyKeyIsSentAsAHeader(t *testing.T) {
	var gotHeader string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Idempotency-Key")
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"approval_id": "apr_1", "status": "pending"})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := c.RequestPush("user@example.com", "Login", &PushOptions{IdempotencyKey: "nonce-123"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotHeader != "nonce-123" {
		t.Errorf("Idempotency-Key header = %q, want %q", gotHeader, "nonce-123")
	}
	if _, leaked := gotBody["idempotency_key"]; leaked {
		t.Error("idempotency_key leaked into the request body; it must be a header only")
	}
}

// Omitting the key must not send an empty header: the server treats a present
// but blank Idempotency-Key differently from an absent one.
func TestRequestPush_NoIdempotencyKeySendsNoHeader(t *testing.T) {
	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["Idempotency-Key"]
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"approval_id": "apr_1", "status": "pending"})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if _, err := c.RequestPush("user@example.com", "Login", &PushOptions{TTL: 60}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if present {
		t.Error("Idempotency-Key header was sent despite no key being supplied")
	}
}

// Not linked is (nil, nil), not an error: at login it is the normal answer,
// and making callers inspect an error on the common path is how integrations
// end up swallowing real ones too.
func TestGetEnrolmentReturnsNilWhenNotLinked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("user_identifier"); got != "ada@example.com" {
			t.Errorf("user_identifier = %q, want ada@example.com", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}, "next_cursor": ""})
	}))
	defer srv.Close()

	c := newTestClient(srv)
	e, err := c.GetEnrolment("ada@example.com")
	if err != nil {
		t.Fatalf("GetEnrolment: %v", err)
	}
	if e != nil {
		t.Errorf("GetEnrolment = %+v, want nil", e)
	}
}

func TestGetEnrolmentReturnsEnrolmentWhenLinked(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("user_identifier") != "ada@example.com" {
			t.Errorf("user_identifier = %q", q.Get("user_identifier"))
		}
		if q.Get("limit") != "1" {
			t.Errorf("limit = %q, want 1", q.Get("limit"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"id":"e1","user_identifier":"ada@example.com","created_at":"2026-08-01T10:00:00Z","last_auth_at":null,"last_auth_outcome":null,"push_ready":true}],"next_cursor":""}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	e, err := c.GetEnrolment("ada@example.com")
	if err != nil {
		t.Fatalf("GetEnrolment: %v", err)
	}
	if e == nil {
		t.Fatal("GetEnrolment = nil, want an enrolment")
	}
	if e.ID != "e1" || !e.PushReady {
		t.Errorf("enrolment = %+v", e)
	}
}

// user_identifier is an arbitrary developer-chosen string, unlike
// cursor/sort/order, so it must be genuinely absent from the query when
// unset rather than sent as an empty value.
func TestListEnrolments_UserIdentifierOmittedWhenEmpty(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("user_identifier") {
			t.Errorf("user_identifier must be omitted when unset, got %q", r.URL.Query().Get("user_identifier"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"next_cursor":""}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if _, err := c.ListEnrolments(&ListEnrolmentsOptions{}); err != nil {
		t.Fatalf("ListEnrolments: %v", err)
	}
}

func TestListEnrolments_UserIdentifierIncludedWhenSet(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("user_identifier"); got != "alice@acme.com" {
			t.Errorf("user_identifier = %q, want alice@acme.com", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[],"next_cursor":""}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if _, err := c.ListEnrolments(&ListEnrolmentsOptions{UserIdentifier: "alice@acme.com"}); err != nil {
		t.Fatalf("ListEnrolments: %v", err)
	}
}

func TestGetPairingCodeStatus_Pending(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/sdk/pairing-codes/af17-b500" {
			t.Errorf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	st, err := c.GetPairingCodeStatus("af17-b500")
	if err != nil {
		t.Fatalf("GetPairingCodeStatus: %v", err)
	}
	if st.Status != "pending" || st.EnrolmentID != "" {
		t.Errorf("status = %+v", st)
	}
}

func TestGetPairingCodeStatus_Redeemed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"redeemed","enrolment_id":"e1"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	st, err := c.GetPairingCodeStatus("af17-b500")
	if err != nil {
		t.Fatalf("GetPairingCodeStatus: %v", err)
	}
	if st.Status != "redeemed" || st.EnrolmentID != "e1" {
		t.Errorf("status = %+v", st)
	}
}

// A code that never existed and one belonging to another app must BOTH
// report "expired" — distinguishing them would make the endpoint a probing
// oracle. The client must surface the server's value verbatim, not attempt
// to tell the two apart itself (it has nothing in the payload to do so with).
func TestGetPairingCodeStatus_UnknownOrOtherAppCodeReadsExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"expired"}`))
	}))
	defer srv.Close()

	c := newTestClient(srv)
	st, err := c.GetPairingCodeStatus("never-existed")
	if err != nil {
		t.Fatalf("GetPairingCodeStatus: %v", err)
	}
	if st.Status != "expired" {
		t.Errorf("status = %+v, want expired", st)
	}
}

// The default base URL is a security boundary, not a convenience: a client
// built without BaseURL sends the caller's rka_ key to whatever this names.
// It named https://app.u2secured.io through v0.3.0 -- a domain nobody had
// registered, so any stranger could have bought it and collected keys from
// every integration that took the default. No test referenced the constant,
// so nothing noticed.
//
// The literal is asserted rather than the constant against itself, which
// would pass whatever the constant said.
func TestDefaultBaseURLIsTheProductionHost(t *testing.T) {
	if defaultBaseURL != "https://auth.u2secured.com" {
		t.Fatalf("default base URL = %q, want https://auth.u2secured.com", defaultBaseURL)
	}
}
