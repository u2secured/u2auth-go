package u2auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidSignature        = errors.New("u2auth: invalid webhook signature")
	ErrTimestampOutOfTolerance = errors.New("u2auth: webhook timestamp out of tolerance")
	ErrMalformedSignature      = errors.New("u2auth: malformed signature header")
)

// WebhookEvent is the verified, parsed webhook payload.
type WebhookEvent struct {
	ApprovalID string     `json:"approval_id"`
	Status     string     `json:"status"`
	Reason     string     `json:"reason,omitempty"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

type webhookConfig struct{ tolerance time.Duration }

// WebhookOption configures VerifyWebhook.
type WebhookOption func(*webhookConfig)

// WithTolerance sets the allowed clock skew between the signed timestamp and now.
func WithTolerance(d time.Duration) WebhookOption {
	return func(c *webhookConfig) { c.tolerance = d }
}

// VerifyWebhook checks the X-U2Auth-Signature over the RAW payload and returns
// the parsed event. Pass the raw request body bytes — never a re-serialized object.
func VerifyWebhook(payload []byte, sigHeader, secret string, opts ...WebhookOption) (*WebhookEvent, error) {
	cfg := webhookConfig{tolerance: 300 * time.Second}
	for _, o := range opts {
		o(&cfg)
	}
	t, v1, err := parseSigHeader(sigHeader)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(t, 10) + "." + string(payload)))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(v1)) {
		return nil, ErrInvalidSignature
	}
	if skew := time.Since(time.Unix(t, 0)); skew < -cfg.tolerance || skew > cfg.tolerance {
		return nil, ErrTimestampOutOfTolerance
	}
	var ev WebhookEvent
	if err := json.Unmarshal(payload, &ev); err != nil {
		return nil, err
	}
	return &ev, nil
}

func parseSigHeader(h string) (int64, string, error) {
	var tStr, v1 string
	for _, part := range strings.Split(h, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			tStr = kv[1]
		case "v1":
			v1 = kv[1]
		}
	}
	if tStr == "" || v1 == "" {
		return 0, "", ErrMalformedSignature
	}
	t, err := strconv.ParseInt(tStr, 10, 64)
	if err != nil {
		return 0, "", ErrMalformedSignature
	}
	return t, v1, nil
}
