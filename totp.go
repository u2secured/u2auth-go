package u2auth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	defaultDigits    = 6
	defaultPeriodSec = 30
)

// decodeTOTPSecret accepts padded and unpadded base32, in either case.
func decodeTOTPSecret(s string) []byte {
	s = strings.ToUpper(strings.TrimSpace(s))
	if b, err := base32.StdEncoding.DecodeString(s); err == nil {
		return b
	}
	b, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	return b
}

// GenerateTOTP computes the RFC 6238 code for a secret at an instant. Exposed
// mainly so callers can drive a fixed clock in tests; most want ValidateTOTP.
func GenerateTOTP(secret string, t time.Time, digits, periodSec int) string {
	if digits <= 0 {
		digits = defaultDigits
	}
	if periodSec <= 0 {
		periodSec = defaultPeriodSec
	}
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(t.Unix())/uint64(periodSec))

	mac := hmac.New(sha1.New, decodeTOTPSecret(secret))
	mac.Write(counter)
	h := mac.Sum(nil)

	offset := h[len(h)-1] & 0x0f
	truncated := binary.BigEndian.Uint32(h[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, int(truncated)%int(math.Pow10(digits)))
}

// ValidateTOTP verifies a code locally, without a network call.
//
// It runs the same RFC 6238 check the U2 Secured Authenticator backend runs,
// including the ±1 window tolerance for clock drift, and returns the same
// answer — the shared vectors in sdk/testvectors/totp.json are asserted against
// the backend's own implementation to keep the two from drifting. Prefer this
// when a login must not depend on a third party being reachable: the
// developer's backend already holds the secret, so no round trip is required.
//
// What it does NOT provide, and Client.VerifyTOTP does:
//   - the shared brute-force lockout, which spans all your backend instances
//   - an entry in the Activity feed of the developer portal
//
// Neither call protects against replay on its own — a code stays valid for its
// whole window. Bind a successful check to a single login attempt.
//
// Passing zero for digits or periodSec uses the defaults (6 and 30).
func ValidateTOTP(secret, code string, t time.Time, digits, periodSec int) bool {
	if periodSec <= 0 {
		periodSec = defaultPeriodSec
	}
	supplied := []byte(strings.TrimSpace(code))
	ok := false
	for delta := -1; delta <= 1; delta++ {
		candidate := []byte(GenerateTOTP(secret, t.Add(time.Duration(delta*periodSec)*time.Second), digits, periodSec))
		// Every window is compared, with no early return, so neither the
		// matching window nor the number of correct digits leaks through timing.
		if hmac.Equal(candidate, supplied) {
			ok = true
		}
	}
	return ok
}
