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
