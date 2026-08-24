package u2auth

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"net/url"
	"strings"
)

// QRCodeOptions holds optional parameters for GenerateQRCodeURI.
type QRCodeOptions struct {
	Algorithm string // default: SHA1
	Digits    int    // default: 6
	Period    int    // default: 30
}

// GenerateSecret generates a cryptographically random base32-encoded TOTP secret.
// byteLen controls the entropy size (default 20).
func GenerateSecret(byteLen int) (string, error) {
	if byteLen <= 0 {
		byteLen = 20
	}
	raw := make([]byte, byteLen)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("u2auth: generate secret: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw), nil
}

// GenerateQRCodeURI builds an otpauth://totp/... URI suitable for QR code display.
func GenerateQRCodeURI(issuer, account, secret string, opts *QRCodeOptions) string {
	algorithm := "SHA1"
	digits := 6
	period := 30

	if opts != nil {
		if opts.Algorithm != "" {
			algorithm = opts.Algorithm
		}
		if opts.Digits > 0 {
			digits = opts.Digits
		}
		if opts.Period > 0 {
			period = opts.Period
		}
	}

	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)

	params := url.Values{}
	params.Set("secret", secret)
	params.Set("issuer", issuer)
	params.Set("algorithm", algorithm)
	params.Set("digits", fmt.Sprintf("%d", digits))
	params.Set("period", fmt.Sprintf("%d", period))

	return "otpauth://totp/" + label + "?" + params.Encode()
}

// GenerateRecoveryCodes generates count random 8-character alphanumeric recovery codes.
func GenerateRecoveryCodes(count int) ([]string, error) {
	if count <= 0 {
		count = 10
	}
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	codes := make([]string, count)
	for i := range codes {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("u2auth: generate recovery codes: %w", err)
		}
		var sb strings.Builder
		for _, b := range buf {
			sb.WriteByte(charset[int(b)%len(charset)])
		}
		codes[i] = sb.String()
	}
	return codes, nil
}
