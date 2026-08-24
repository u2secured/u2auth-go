package u2auth

import (
	"encoding/json"
	"os"
	"testing"
	"time"
)

type vectorFile struct {
	Secret          string `json:"secret"`
	Body            string `json:"body"`
	SignatureHeader string `json:"signature_header"`
}

func loadVector(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("../testvectors/webhook.json")
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	return v
}

const bigTolerance = 1_000_000 * time.Hour

func TestVerifyWebhook_Valid(t *testing.T) {
	v := loadVector(t)
	ev, err := VerifyWebhook([]byte(v.Body), v.SignatureHeader, v.Secret, WithTolerance(bigTolerance))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ev.ApprovalID != "ap_test123" || ev.Status != "approved" || ev.Reason != "user_approved" || ev.ResolvedAt == nil {
		t.Fatalf("event = %+v", ev)
	}
}

func TestVerifyWebhook_TamperedBody(t *testing.T) {
	v := loadVector(t)
	if _, err := VerifyWebhook([]byte(v.Body+" "), v.SignatureHeader, v.Secret, WithTolerance(bigTolerance)); err != ErrInvalidSignature {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
}

func TestVerifyWebhook_WrongSecret(t *testing.T) {
	v := loadVector(t)
	if _, err := VerifyWebhook([]byte(v.Body), v.SignatureHeader, "wrong", WithTolerance(bigTolerance)); err != ErrInvalidSignature {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
}

func TestVerifyWebhook_ExpiredTimestamp(t *testing.T) {
	v := loadVector(t)
	if _, err := VerifyWebhook([]byte(v.Body), v.SignatureHeader, v.Secret); err != ErrTimestampOutOfTolerance {
		t.Fatalf("want ErrTimestampOutOfTolerance, got %v", err)
	}
}
