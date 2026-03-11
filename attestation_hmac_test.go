package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func signHMACTestValue(deviceID, timestamp, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(deviceID + timestamp))
	return hex.EncodeToString(mac.Sum(nil))
}

func TestHMACAttestationProviderVerify(t *testing.T) {
	provider := HMACAttestationProvider{}
	appConfig.Attestation.MaxAgeSeconds = 60
	appConfig.Attestation.HeaderName = "X-Device-Id"
	hmacSecretLookupMap = map[string]string{"mobile-test": "super-secret"}

	now := time.Now().Unix()
	timestamp := strconv.FormatInt(now, 10)
	deviceID := "device-123"
	signature := signHMACTestValue(deviceID, timestamp, "super-secret")

	t.Run("valid signature", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/token", nil)
		req.Header.Set("X-Device-Id", deviceID)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Signature", signature)

		result, err := provider.Verify(req.Context(), deviceID, req, "mobile-test", "mobile")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if result == nil || result.Level != "hmac" {
			t.Fatalf("expected hmac level result, got: %+v", result)
		}
	})

	t.Run("missing timestamp header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/token", nil)
		req.Header.Set("X-Device-Id", deviceID)
		req.Header.Set("X-Signature", signature)

		_, err := provider.Verify(req.Context(), deviceID, req, "mobile-test", "mobile")
		if err == nil || !strings.Contains(err.Error(), "X-Timestamp") {
			t.Fatalf("expected X-Timestamp error, got: %v", err)
		}
	})

	t.Run("too old timestamp", func(t *testing.T) {
		oldTs := strconv.FormatInt(time.Now().Add(-2*time.Minute).Unix(), 10)
		oldSig := signHMACTestValue(deviceID, oldTs, "super-secret")

		req := httptest.NewRequest(http.MethodPost, "/token", nil)
		req.Header.Set("X-Device-Id", deviceID)
		req.Header.Set("X-Timestamp", oldTs)
		req.Header.Set("X-Signature", oldSig)

		_, err := provider.Verify(req.Context(), deviceID, req, "mobile-test", "mobile")
		if err == nil || !strings.Contains(err.Error(), "too old") {
			t.Fatalf("expected stale timestamp error, got: %v", err)
		}
	})

	t.Run("invalid signature", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/token", nil)
		req.Header.Set("X-Device-Id", deviceID)
		req.Header.Set("X-Timestamp", timestamp)
		req.Header.Set("X-Signature", "deadbeef")

		_, err := provider.Verify(req.Context(), deviceID, req, "mobile-test", "mobile")
		if err == nil || !strings.Contains(err.Error(), "mismatch") {
			t.Fatalf("expected signature mismatch error, got: %v", err)
		}
	})
}

func TestTokenHandler_HMACAttestationFlow(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	if err := loadTestKey(); err != nil {
		t.Skipf("Could not load test key: %v", err)
		return
	}

	appConfig.Attestation.Enabled = true
	appConfig.Attestation.RequiredFor = []string{"mobile"}
	appConfig.Attestation.Provider = "hmac"
	appConfig.Attestation.HeaderName = "X-Device-Id"
	appConfig.Attestation.MaxAgeSeconds = 60
	initAttestationProvider()

	clientLookupMap = map[string]string{"mobile-test": "mobile"}
	audienceLookupMap = map[string][]string{"mobile-test": {"mobile-audience"}}
	ttlLookupMap = map[string]time.Duration{"mobile-test": time.Hour}
	hmacSecretLookupMap = map[string]string{"mobile-test": "super-secret"}
	appConfig.PublicHost = "http://localhost:8080"

	form := url.Values{}
	form.Set("client_id", "mobile-test")
	form.Set("grant_type", "client_credentials")

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	deviceID := "device-123"
	signature := signHMACTestValue(deviceID, timestamp, "super-secret")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Device-Id", deviceID)
	req.Header.Set("X-Timestamp", timestamp)
	req.Header.Set("X-Signature", signature)
	w := httptest.NewRecorder()

	tokenHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}
