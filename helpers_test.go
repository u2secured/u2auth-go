package u2auth

import (
	"encoding/base32"
	"strings"
	"testing"
)

func TestGenerateSecret_Base32Valid(t *testing.T) {
	secret, err := GenerateSecret(20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if secret == "" {
		t.Fatal("secret is empty")
	}
	// Must be valid base32 (no padding)
	_, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("secret is not valid base32: %v", err)
	}
}

func TestGenerateSecret_Uniqueness(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 20; i++ {
		s, err := GenerateSecret(20)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if seen[s] {
			t.Fatalf("duplicate secret generated: %s", s)
		}
		seen[s] = true
	}
}

func TestGenerateSecret_DefaultByteLen(t *testing.T) {
	secret, err := GenerateSecret(0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secret) == 0 {
		t.Fatal("empty secret for default byte len")
	}
}

func TestGenerateQRCodeURI_Format(t *testing.T) {
	uri := GenerateQRCodeURI("Acme Corp", "user@example.com", "JBSWY3DPEHPK3PXP", nil)
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("URI does not start with otpauth://totp/: %s", uri)
	}
}

func TestGenerateQRCodeURI_ContainsFields(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	uri := GenerateQRCodeURI("MyApp", "alice@example.com", secret, nil)

	if !strings.Contains(uri, "secret="+secret) {
		t.Errorf("URI missing secret field: %s", uri)
	}
	if !strings.Contains(uri, "issuer=MyApp") {
		t.Errorf("URI missing issuer field: %s", uri)
	}
	if !strings.Contains(uri, "algorithm=SHA1") {
		t.Errorf("URI missing algorithm field: %s", uri)
	}
	if !strings.Contains(uri, "digits=6") {
		t.Errorf("URI missing digits field: %s", uri)
	}
	if !strings.Contains(uri, "period=30") {
		t.Errorf("URI missing period field: %s", uri)
	}
}

func TestGenerateQRCodeURI_CustomOpts(t *testing.T) {
	opts := &QRCodeOptions{
		Algorithm: "SHA256",
		Digits:    8,
		Period:    60,
	}
	uri := GenerateQRCodeURI("MyApp", "bob@example.com", "SECRET", opts)

	if !strings.Contains(uri, "algorithm=SHA256") {
		t.Errorf("URI missing custom algorithm: %s", uri)
	}
	if !strings.Contains(uri, "digits=8") {
		t.Errorf("URI missing custom digits: %s", uri)
	}
	if !strings.Contains(uri, "period=60") {
		t.Errorf("URI missing custom period: %s", uri)
	}
}

func TestGenerateRecoveryCodes_Count(t *testing.T) {
	codes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(codes) != 10 {
		t.Fatalf("expected 10 codes, got %d", len(codes))
	}
}

func TestGenerateRecoveryCodes_Length(t *testing.T) {
	codes, err := GenerateRecoveryCodes(5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, c := range codes {
		if len(c) != 8 {
			t.Errorf("code %q has length %d, want 8", c, len(c))
		}
	}
}

func TestGenerateRecoveryCodes_Uniqueness(t *testing.T) {
	codes, err := GenerateRecoveryCodes(20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	seen := make(map[string]bool)
	for _, c := range codes {
		if seen[c] {
			t.Errorf("duplicate recovery code: %s", c)
		}
		seen[c] = true
	}
}

func TestGenerateRecoveryCodes_Alphanumeric(t *testing.T) {
	codes, err := GenerateRecoveryCodes(10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	const valid = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for _, code := range codes {
		for _, ch := range code {
			if !strings.ContainsRune(valid, ch) {
				t.Errorf("code %q contains invalid character %c", code, ch)
			}
		}
	}
}
