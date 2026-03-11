package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type failingAttestationProvider struct{}

func (failingAttestationProvider) Verify(_ context.Context, _ string, _ *http.Request, _, _ string) (*AttestationResult, error) {
	return nil, errors.New("provider rejected token")
}

func setupTokenHandlerBaseConfig() {
	clientLookupMap = map[string]string{"mobile-test": "mobile", "web-test": "web"}
	originLookupMap = map[string][]string{"web-test": {"*"}}
	audienceLookupMap = map[string][]string{"mobile-test": {"mobile-aud"}, "web-test": {"web-aud"}}
	ttlLookupMap = map[string]time.Duration{"mobile-test": time.Hour, "web-test": time.Hour}
	appConfig.PublicHost = "http://localhost:8080"
	appConfig.Attestation.HeaderName = "X-Device-Id"
	appConfig.Attestation.FormField = "device_id"
}

func TestExtractAttestationToken(t *testing.T) {
	appConfig.Attestation.HeaderName = "X-Device-Id"
	appConfig.Attestation.FormField = "device_id"

	t.Run("header takes precedence over device_id", func(t *testing.T) {
		form := url.Values{}
		form.Set("device_id", "device-token")
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Device-Id", "header-token")
		_ = req.ParseForm()

		if got := extractAttestationToken(req); got != "header-token" {
			t.Fatalf("expected header token, got: %s", got)
		}
	})

	t.Run("uses device_id as attestation token", func(t *testing.T) {
		form := url.Values{}
		form.Set("device_id", "my-attestation-payload")
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = req.ParseForm()

		if got := extractAttestationToken(req); got != "my-attestation-payload" {
			t.Fatalf("expected device_id as attestation token, got: %s", got)
		}
	})

	t.Run("returns empty if nothing provided", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/token", nil)
		if got := extractAttestationToken(req); got != "" {
			t.Fatalf("expected empty, got: %s", got)
		}
	})
}

func TestTokenHandler_AttestationEnforcement(t *testing.T) {
	originalLogger := appLogger
	originalProvider := attestationProvider
	defer func() {
		appLogger = originalLogger
		attestationProvider = originalProvider
	}()
	appLogger = &TextLogger{}

	if err := loadTestKey(); err != nil {
		t.Skipf("Could not load test key: %v", err)
		return
	}
	setupTokenHandlerBaseConfig()

	t.Run("disabled attestation allows token without attestation", func(t *testing.T) {
		appConfig.Attestation.Enabled = false
		attestationProvider = NoopAttestationProvider{}

		form := url.Values{}
		form.Set("client_id", "mobile-test")
		form.Set("grant_type", "client_credentials")
		form.Set("device_id", "device-attestation-payload")

		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		tokenHandler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("enabled attestation rejects missing device_id", func(t *testing.T) {
		appConfig.Attestation.Enabled = true
		appConfig.Attestation.RequiredFor = []string{"mobile"}
		attestationProvider = NoopAttestationProvider{}

		// No device_id -> missing both for mobile check and attestation
		form := url.Values{}
		form.Set("client_id", "mobile-test")
		form.Set("grant_type", "client_credentials")

		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		tokenHandler(w, req)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("enabled attestation rejects invalid device_id token", func(t *testing.T) {
		appConfig.Attestation.Enabled = true
		appConfig.Attestation.RequiredFor = []string{"mobile"}
		attestationProvider = failingAttestationProvider{}

		form := url.Values{}
		form.Set("client_id", "mobile-test")
		form.Set("grant_type", "client_credentials")
		form.Set("device_id", "bad-attestation-payload")

		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		tokenHandler(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", w.Code, w.Body.String())
		}
	})

	t.Run("enabled attestation adds attested claims using device_id", func(t *testing.T) {
		appConfig.Attestation.Enabled = true
		appConfig.Attestation.RequiredFor = []string{"mobile"}
		attestationProvider = NoopAttestationProvider{}

		// Mobile client sends device_id — this is the attestation token
		form := url.Values{}
		form.Set("client_id", "mobile-test")
		form.Set("grant_type", "client_credentials")
		form.Set("device_id", "my-device-attestation-payload")

		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		tokenHandler(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
		}

		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("failed to parse token response: %v", err)
		}
		tokenString, ok := response["access_token"].(string)
		if !ok {
			t.Fatal("missing access_token")
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			keyMu.RLock()
			defer keyMu.RUnlock()
			return &signingKey.PublicKey, nil
		})
		if err != nil {
			t.Fatalf("failed to parse jwt: %v", err)
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			t.Fatal("missing claims")
		}
		if claims["attested"] != true {
			t.Fatalf("expected attested=true, got: %v", claims["attested"])
		}
		if claims["attestation_level"] != "stub" {
			t.Fatalf("expected attestation_level=stub, got: %v", claims["attestation_level"])
		}
		if claims["device_id"] != "my-device-attestation-payload" {
			t.Fatalf("expected device_id claim preserved, got: %v", claims["device_id"])
		}
	})
}
