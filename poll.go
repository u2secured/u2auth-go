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

// WaitForLinkOptions tunes WaitForLink. A zero Interval or Timeout takes the
// default (2s and 2m respectively).
type WaitForLinkOptions struct {
	// UserIdentifier is the identifier the code was minted for. Required —
	// used to fetch the enrolment once the code is redeemed.
	UserIdentifier string
	Interval       time.Duration
	Timeout        time.Duration
}

// WaitForLink polls a pairing code until the user redeems it, then returns
// the resulting enrolment. The link half of link-then-push, mirroring
// WaitForApproval.
//
// Blocks. Returns an *APIError with Code "MISSING_USER_IDENTIFIER" if
// opts is nil or opts.UserIdentifier is empty — checked before any request is
// made, since a Go string parameter is legitimately "" at runtime and the
// compiler cannot rule that out the way a required field can in a stricter
// language. Otherwise returns "PAIRING_CODE_EXPIRED" if the code lapses
// first, "LINK_TIMEOUT" once the deadline passes, "ENROLMENT_NOT_FOUND" if
// the code is reported redeemed but no matching enrolment can be found for
// UserIdentifier (redemption and the enrolment lookup are two separate
// backend calls and can disagree), or ctx.Err() if the context is cancelled.
func (c *Client) WaitForLink(ctx context.Context, code string, opts *WaitForLinkOptions) (*Enrolment, error) {
	if opts == nil || opts.UserIdentifier == "" {
		return nil, &APIError{Code: "MISSING_USER_IDENTIFIER", Message: "WaitForLink requires opts.UserIdentifier"}
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	deadline := time.Now().Add(timeout)

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		status, err := c.GetPairingCodeStatus(code)
		if err != nil {
			return nil, err
		}
		switch status.Status {
		case "redeemed":
			e, err := c.GetEnrolment(opts.UserIdentifier)
			if err != nil {
				return nil, err
			}
			if e == nil {
				return nil, &APIError{
					Code:    "ENROLMENT_NOT_FOUND",
					Message: "pairing code was redeemed but no enrolment was found for this identifier",
				}
			}
			return e, nil
		case "expired":
			return nil, &APIError{Code: "PAIRING_CODE_EXPIRED", Message: "pairing code expired before it was redeemed"}
		}

		if time.Now().After(deadline) {
			return nil, &APIError{Code: "LINK_TIMEOUT", Message: "timed out waiting for the pairing code to be redeemed"}
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}
	}
}
