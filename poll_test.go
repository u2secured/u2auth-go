package u2auth

import (
	"context"
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
