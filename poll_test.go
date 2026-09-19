package u2auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestWaitForApproval_PendingThenApproved(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		w.WriteHeader(200)
		if n < 3 {
			_, _ = w.Write([]byte(`{"approval_id":"ap1","status":"pending"}`))
		} else {
			_, _ = w.Write([]byte(`{"approval_id":"ap1","status":"approved"}`))
		}
	}))
	defer srv.Close()
	c := NewClient("k", &ClientOptions{BaseURL: srv.URL})
	st, err := c.WaitForApproval(context.Background(), "ap1", &WaitOptions{Interval: 5 * time.Millisecond, Timeout: time.Second})
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	if st.Status != "approved" {
		t.Fatalf("status = %s", st.Status)
	}
}

func TestWaitForApproval_Timeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"approval_id":"ap1","status":"pending"}`))
	}))
	defer srv.Close()
	c := NewClient("k", &ClientOptions{BaseURL: srv.URL})
	if _, err := c.WaitForApproval(context.Background(), "ap1", &WaitOptions{Interval: 5 * time.Millisecond, Timeout: 40 * time.Millisecond}); err != ErrWaitTimeout {
		t.Fatalf("want ErrWaitTimeout, got %v", err)
	}
}

func TestWaitForLinkExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "expired"})
	}))
	defer srv.Close()

	c := NewClient("rka_test", &ClientOptions{BaseURL: srv.URL})
	_, err := c.WaitForLink(context.Background(), "af17-b500", &WaitForLinkOptions{
		UserIdentifier: "ada@example.com",
		Interval:       time.Millisecond,
	})

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "PAIRING_CODE_EXPIRED" {
		t.Fatalf("WaitForLink err = %v, want APIError PAIRING_CODE_EXPIRED", err)
	}
}

func TestWaitForLinkTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
	}))
	defer srv.Close()

	c := NewClient("rka_test", &ClientOptions{BaseURL: srv.URL})
	_, err := c.WaitForLink(context.Background(), "af17-b500", &WaitForLinkOptions{
		UserIdentifier: "ada@example.com",
		Interval:       time.Millisecond,
		Timeout:        3 * time.Millisecond,
	})

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "LINK_TIMEOUT" {
		t.Fatalf("WaitForLink err = %v, want APIError LINK_TIMEOUT", err)
	}
}

// The context is the Go-idiomatic cancellation channel; the other SDKs use a
// signal or have none.
func TestWaitForLinkHonoursContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := NewClient("rka_test", &ClientOptions{BaseURL: srv.URL})
	if _, err := c.WaitForLink(ctx, "af17-b500", &WaitForLinkOptions{
		UserIdentifier: "ada@example.com",
		Interval:       time.Millisecond,
	}); err == nil {
		t.Fatal("WaitForLink with a cancelled context: err = nil, want non-nil")
	}
}

func TestWaitForLinkRedeemedReturnsEnrolment(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/sdk/pairing-codes/af17-b500" {
			n := atomic.AddInt32(&calls, 1)
			w.Header().Set("Content-Type", "application/json")
			if n < 2 {
				_, _ = w.Write([]byte(`{"status":"pending"}`))
			} else {
				_, _ = w.Write([]byte(`{"status":"redeemed","enrolment_id":"e1"}`))
			}
			return
		}
		// GET /api/v1/sdk/enrolments — the lookup WaitForLink makes once
		// redemption is observed.
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"id":"e1","user_identifier":"ada@example.com","created_at":"2026-08-01T10:00:00Z","last_auth_at":null,"last_auth_outcome":null,"push_ready":true}],"next_cursor":""}`))
	}))
	defer srv.Close()

	c := NewClient("rka_test", &ClientOptions{BaseURL: srv.URL})
	e, err := c.WaitForLink(context.Background(), "af17-b500", &WaitForLinkOptions{
		UserIdentifier: "ada@example.com",
		Interval:       time.Millisecond,
		Timeout:        time.Second,
	})
	if err != nil {
		t.Fatalf("WaitForLink: %v", err)
	}
	if e == nil || e.ID != "e1" || !e.PushReady {
		t.Errorf("enrolment = %+v", e)
	}
}

// The pairing-code redemption and the enrolment lookup are two separate
// backend calls, and they can disagree: this pins that disagreement surfaces
// as ENROLMENT_NOT_FOUND rather than a nil enrolment or a panic.
func TestWaitForLinkRedeemedButNoEnrolmentFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/sdk/pairing-codes/af17-b500" {
			_, _ = w.Write([]byte(`{"status":"redeemed","enrolment_id":"e1"}`))
			return
		}
		_, _ = w.Write([]byte(`{"items":[],"next_cursor":""}`))
	}))
	defer srv.Close()

	c := NewClient("rka_test", &ClientOptions{BaseURL: srv.URL})
	_, err := c.WaitForLink(context.Background(), "af17-b500", &WaitForLinkOptions{
		UserIdentifier: "ada@example.com",
		Interval:       time.Millisecond,
		Timeout:        time.Second,
	})

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "ENROLMENT_NOT_FOUND" {
		t.Fatalf("WaitForLink err = %v, want APIError ENROLMENT_NOT_FOUND", err)
	}
}

// Ruling PF6: Go has no non-empty-string type, so unlike the Node SDK (which
// can lean on a required TypeScript field), the empty-identifier guard must
// be an explicit runtime check here — without it an empty identifier is
// silently omitted from the query and redemption can return an unrelated
// enrolment. The server is never reached if this regresses back to a hang,
// so give the request a context deadline well under Go's test timeout: a
// regression must show up as a fast test failure, not a hung/timed-out CI
// run.
func TestWaitForLinkMissingUserIdentifier(t *testing.T) {
	var called bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"pending"}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Millisecond)
	defer cancel()

	c := NewClient("rka_test", &ClientOptions{BaseURL: srv.URL})
	_, err := c.WaitForLink(ctx, "af17-b500", &WaitForLinkOptions{
		UserIdentifier: "",
		Interval:       time.Millisecond,
	})

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "MISSING_USER_IDENTIFIER" {
		t.Fatalf("WaitForLink err = %v, want APIError MISSING_USER_IDENTIFIER", err)
	}
	if called {
		t.Error("WaitForLink must reject a missing user identifier before making any request")
	}
}

func TestWaitForLinkNilOptions(t *testing.T) {
	c := NewClient("rka_test", &ClientOptions{BaseURL: "http://127.0.0.1:0"})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Millisecond)
	defer cancel()

	_, err := c.WaitForLink(ctx, "af17-b500", nil)

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "MISSING_USER_IDENTIFIER" {
		t.Fatalf("WaitForLink err = %v, want APIError MISSING_USER_IDENTIFIER", err)
	}
}
