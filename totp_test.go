package u2auth

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

type totpVectors struct {
	Digits    int `json:"digits"`
	PeriodSec int `json:"period_sec"`
	Cases     []struct {
		Name   string `json:"name"`
		Secret string `json:"secret"`
		Time   int64  `json:"time"`
		Code   string `json:"code"`
		Valid  bool   `json:"valid"`
	} `json:"cases"`
}

// The same vectors the backend asserts itself against — this is what stops
// local validation answering differently from the server.
func TestValidateTOTP_SharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../testvectors/totp.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v totpVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(v.Cases) == 0 {
		t.Fatal("no cases in vector file")
	}
	for _, c := range v.Cases {
		if got := ValidateTOTP(c.Secret, c.Code, time.Unix(c.Time, 0), v.Digits, v.PeriodSec); got != c.Valid {
			t.Errorf("%s: got %v, want %v", c.Name, got, c.Valid)
		}
	}
}

func TestValidateTOTP_RoundTrip(t *testing.T) {
	secret, err := GenerateSecret(20)
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := time.Now()
	if !ValidateTOTP(secret, GenerateTOTP(secret, now, 0, 0), now, 0, 0) {
		t.Error("a freshly generated secret should validate its own current code")
	}
}

func TestValidateTOTP_RejectsMalformedCode(t *testing.T) {
	secret, _ := GenerateSecret(20)
	for _, code := range []string{"", "12345", "abcdef"} {
		if ValidateTOTP(secret, code, time.Now(), 0, 0) {
			t.Errorf("code %q should not validate", code)
		}
	}
}
