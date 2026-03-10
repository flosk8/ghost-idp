package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestFormatHost(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "http already present",
			input:    "http://example.com",
			expected: "http://example.com",
		},
		{
			name:     "https already present",
			input:    "https://example.com",
			expected: "https://example.com",
		},
		{
			name:     "no protocol - should add https",
			input:    "example.com",
			expected: "https://example.com",
		},
		{
			name:     "localhost",
			input:    "localhost:8080",
			expected: "https://localhost:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatHost(tt.input)
			if result != tt.expected {
				t.Errorf("formatHost(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestJWKSHandler(t *testing.T) {
	// Save original state
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	t.Run("no signing key loaded", func(t *testing.T) {
		keyMu.Lock()
		originalKey := signingKey
		signingKey = nil
		keyMu.Unlock()
		defer func() {
			keyMu.Lock()
			signingKey = originalKey
			keyMu.Unlock()
		}()

		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		w := httptest.NewRecorder()

		jwksHandler(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got: %d", w.Code)
		}
	})

	t.Run("signing key loaded", func(t *testing.T) {
		// Load a test key first
		if err := loadTestKey(); err != nil {
			t.Skipf("Could not load test key: %v", err)
			return
		}

		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		w := httptest.NewRecorder()

		jwksHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got: %d", w.Code)
		}

		contentType := w.Header().Get("Content-Type")
		if !strings.Contains(contentType, "application/json") {
			t.Errorf("Expected Content-Type application/json, got: %s", contentType)
		}

		var response map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to parse JSON response: %v", err)
		}

		keys, ok := response["keys"].([]interface{})
		if !ok || len(keys) == 0 {
			t.Error("Expected 'keys' array in response")
		}
	})
}

func TestTokenHandler_MissingClientID(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	form := url.Values{}
	form.Set("grant_type", "client_credentials")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got: %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "client_id is required") {
		t.Errorf("Expected error message about client_id, got: %s", body)
	}
}

func TestTokenHandler_MissingGrantType(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	form := url.Values{}
	form.Set("client_id", "test-client")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got: %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "grant_type is required") {
		t.Errorf("Expected error message about grant_type, got: %s", body)
	}
}

func TestTokenHandler_InvalidGrantType(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	form := url.Values{}
	form.Set("client_id", "test-client")
	form.Set("grant_type", "invalid_grant")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got: %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "unsupported_grant_type") {
		t.Errorf("Expected error message about unsupported_grant_type, got: %s", body)
	}
}

func TestTokenHandler_InvalidClient(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	// Initialize empty client lookup
	clientLookupMap = make(map[string]string)

	form := url.Values{}
	form.Set("client_id", "invalid-client")
	form.Set("grant_type", "client_credentials")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got: %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Invalid client_id") {
		t.Errorf("Expected error message about invalid client_id, got: %s", body)
	}
}

func TestTokenHandler_MobileWithoutDeviceID(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	// Setup mobile client
	clientLookupMap = map[string]string{
		"mobile-test": "mobile",
	}

	form := url.Values{}
	form.Set("client_id", "mobile-test")
	form.Set("grant_type", "client_credentials")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got: %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "device_id is required") {
		t.Errorf("Expected error message about device_id, got: %s", body)
	}
}

func TestTokenHandler_WebWithoutOrigin(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	// Setup web client
	clientLookupMap = map[string]string{
		"web-test": "web",
	}

	form := url.Values{}
	form.Set("client_id", "web-test")
	form.Set("grant_type", "client_credentials")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got: %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Origin header is required") {
		t.Errorf("Expected error message about Origin header, got: %s", body)
	}
}

func TestTokenHandler_WebWithInvalidOrigin(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	// Setup web client with allowed origins
	clientLookupMap = map[string]string{
		"web-test": "web",
	}
	originLookupMap = map[string][]string{
		"web-test": {"https://allowed.com"},
	}

	form := url.Values{}
	form.Set("client_id", "web-test")
	form.Set("grant_type", "client_credentials")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://malicious.com")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got: %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Origin not allowed") {
		t.Errorf("Expected error message about origin not allowed, got: %s", body)
	}
}

func TestTokenHandler_WebWithWildcardOrigin(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	// Load test key
	if err := loadTestKey(); err != nil {
		t.Skipf("Could not load test key: %v", err)
		return
	}

	// Setup web client with wildcard origin
	clientLookupMap = map[string]string{
		"web-test": "web",
	}
	originLookupMap = map[string][]string{
		"web-test": {"*"},
	}
	audienceLookupMap = map[string][]string{
		"web-test": {"test-audience"},
	}
	ttlLookupMap = map[string]time.Duration{
		"web-test": 2 * time.Hour,
	}
	appConfig.PublicHost = "http://localhost:8080"

	form := url.Values{}
	form.Set("client_id", "web-test")
	form.Set("grant_type", "client_credentials")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://any-origin.com")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got: %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	if _, ok := response["access_token"]; !ok {
		t.Error("Expected access_token in response")
	}
	if response["token_type"] != "Bearer" {
		t.Errorf("Expected token_type Bearer, got: %v", response["token_type"])
	}
}

func TestTokenHandler_SuccessfulMobileToken(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	// Load test key
	if err := loadTestKey(); err != nil {
		t.Skipf("Could not load test key: %v", err)
		return
	}

	// Setup mobile client
	clientLookupMap = map[string]string{
		"mobile-test": "mobile",
	}
	audienceLookupMap = map[string][]string{
		"mobile-test": {"mobile-audience"},
	}
	ttlLookupMap = map[string]time.Duration{
		"mobile-test": 2 * time.Hour,
	}
	appConfig.PublicHost = "http://localhost:8080"

	form := url.Values{}
	form.Set("client_id", "mobile-test")
	form.Set("grant_type", "client_credentials")
	form.Set("device_id", "test-device-123")

	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got: %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	tokenString, ok := response["access_token"].(string)
	if !ok {
		t.Fatal("Expected access_token in response")
	}

	// Parse and verify token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		keyMu.RLock()
		defer keyMu.RUnlock()
		return &signingKey.PublicKey, nil
	})

	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	if !token.Valid {
		t.Error("Token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Failed to get claims")
	}

	// Verify claims
	if claims["client_id"] != "mobile-test" {
		t.Errorf("Expected client_id mobile-test, got: %v", claims["client_id"])
	}
	if claims["device_id"] != "test-device-123" {
		t.Errorf("Expected device_id test-device-123, got: %v", claims["device_id"])
	}
	if claims["role"] != "guest" {
		t.Errorf("Expected role guest, got: %v", claims["role"])
	}
}

// Helper function to load a test key
func loadTestKey() error {
	// Use the existing key if it exists
	appConfig.KeyPath = "tls.key"
	return loadKey()
}

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	healthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got: %d", w.Code)
	}

	if w.Body.String() != "ok" {
		t.Errorf("Expected body 'ok', got: %q", w.Body.String())
	}
}

func TestReadyHandler(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	t.Run("key not loaded", func(t *testing.T) {
		keyMu.Lock()
		originalKey := signingKey
		signingKey = nil
		keyMu.Unlock()
		defer func() {
			keyMu.Lock()
			signingKey = originalKey
			keyMu.Unlock()
		}()

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		w := httptest.NewRecorder()

		readyHandler(w, req)

		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("Expected status 503, got: %d", w.Code)
		}
	})

	t.Run("key loaded", func(t *testing.T) {
		if err := loadTestKey(); err != nil {
			t.Skipf("Could not load test key: %v", err)
			return
		}

		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		w := httptest.NewRecorder()

		readyHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got: %d", w.Code)
		}

		if w.Body.String() != "ready" {
			t.Errorf("Expected body 'ready', got: %q", w.Body.String())
		}
	})
}

func TestJWKSHandlerCORS(t *testing.T) {
	if err := loadTestKey(); err != nil {
		t.Skipf("Could not load test key: %v", err)
		return
	}

	t.Run("GET request includes CORS headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		w := httptest.NewRecorder()

		jwksHandler(w, req)

		corsOrigin := w.Header().Get("Access-Control-Allow-Origin")
		if corsOrigin != "*" {
			t.Errorf("Expected Access-Control-Allow-Origin *, got: %s", corsOrigin)
		}
	})

	t.Run("OPTIONS request returns 204", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/.well-known/jwks.json", nil)
		w := httptest.NewRecorder()

		jwksHandler(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("Expected status 204, got: %d", w.Code)
		}
	})
}
