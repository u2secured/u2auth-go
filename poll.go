package u2auth

import (
	"context"
	"errors"
	"time"
)

// ErrWaitTimeout is returned when WaitForApproval exceeds its timeout.
var ErrWaitTimeout = errors.New("u2auth: timed out waiting for approval")

// WaitOptions configures WaitForApproval. Zero fields use the defaults (2s / 120s).
type WaitOptions struct {
	Interval time.Duration
	Timeout  time.Duration
}

// WaitForApproval polls GetPushStatus until the approval is no longer pending,
// the timeout elapses (ErrWaitTimeout), or ctx is cancelled.
func (c *Client) WaitForApproval(ctx context.Context, approvalID string, opts *WaitOptions) (*PushStatus, error) {
	interval, timeout := 2*time.Second, 120*time.Second
	if opts != nil {
		if opts.Interval > 0 {
			interval = opts.Interval
		}
		if opts.Timeout > 0 {
			timeout = opts.Timeout
		}
	}
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		st, err := c.GetPushStatus(approvalID)
		if err != nil {
			return nil, err
		}
		if st.Status != "pending" {
			return st, nil
		}
		if time.Now().After(deadline) {
			return nil, ErrWaitTimeout
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
