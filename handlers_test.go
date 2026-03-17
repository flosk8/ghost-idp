package main

import (
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
		originalKey := currentKey
		currentKey = nil
		keyMu.Unlock()
		defer func() {
			keyMu.Lock()
			currentKey = originalKey
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

	req := httptest.NewRequest(http.MethodPost, "/sso/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got: %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, `"error":"invalid_request"`) {
		t.Errorf("Expected OAuth error invalid_request, got: %s", body)
	}
	if !strings.Contains(body, "client_id is required") {
		t.Errorf("Expected error description about client_id, got: %s", body)
	}
}

func TestTokenHandler_MissingGrantType(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	form := url.Values{}
	form.Set("client_id", "test-client")

	req := httptest.NewRequest(http.MethodPost, "/sso/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got: %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, `"error":"invalid_request"`) {
		t.Errorf("Expected OAuth error invalid_request, got: %s", body)
	}
	if !strings.Contains(body, "grant_type is required") {
		t.Errorf("Expected error description about grant_type, got: %s", body)
	}
}

func TestTokenHandler_InvalidGrantType(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	form := url.Values{}
	form.Set("client_id", "test-client")
	form.Set("grant_type", "invalid_grant")

	req := httptest.NewRequest(http.MethodPost, "/sso/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got: %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, `"error":"unsupported_grant_type"`) {
		t.Errorf("Expected OAuth error unsupported_grant_type, got: %s", body)
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

	req := httptest.NewRequest(http.MethodPost, "/sso/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got: %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, `"error":"invalid_client"`) {
		t.Errorf("Expected OAuth error invalid_client, got: %s", body)
	}
	if got := w.Header().Get("WWW-Authenticate"); !strings.Contains(got, "invalid_client") {
		t.Errorf("Expected WWW-Authenticate invalid_client, got: %s", got)
	}
}

func TestTokenHandler_MobileWithoutDeviceIDHeader(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodPost, "/sso/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got: %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "device_id") {
		t.Errorf("Expected error description about device_id, got: %s", body)
	}
	if !strings.Contains(body, `"error":"invalid_request"`) {
		t.Errorf("Expected OAuth error invalid_request, got: %s", body)
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

	req := httptest.NewRequest(http.MethodPost, "/sso/token", strings.NewReader(form.Encode()))
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

	req := httptest.NewRequest(http.MethodPost, "/sso/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://malicious.com")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got: %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, `"error":"invalid_client"`) {
		t.Errorf("Expected OAuth error invalid_client, got: %s", body)
	}
	if !strings.Contains(body, "origin not allowed") {
		t.Errorf("Expected error description about origin not allowed, got: %s", body)
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

	req := httptest.NewRequest(http.MethodPost, "/sso/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://any-origin.com")
	w := httptest.NewRecorder()

	tokenHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got: %d", w.Code)
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Expected Cache-Control no-store, got: %s", got)
	}
	if got := w.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Expected Pragma no-cache, got: %s", got)
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

	req := httptest.NewRequest(http.MethodPost, "/sso/token", strings.NewReader(form.Encode()))
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
		return &currentKey.key.PublicKey, nil
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
		originalKey := currentKey
		currentKey = nil
		keyMu.Unlock()
		defer func() {
			keyMu.Lock()
			currentKey = originalKey
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

func TestExtractClientIP(t *testing.T) {
	tests := []struct {
		name       string
		xff        string
		xRealIP    string
		remoteAddr string
		expected   string
	}{
		{name: "uses first IP from X-Forwarded-For", xff: "203.0.113.10, 10.0.0.1", remoteAddr: "10.1.1.1:1234", expected: "203.0.113.10"},
		{name: "falls back to X-Real-IP", xRealIP: "198.51.100.7", remoteAddr: "10.1.1.1:1234", expected: "198.51.100.7"},
		{name: "falls back to RemoteAddr host", remoteAddr: "192.0.2.55:54321", expected: "192.0.2.55"},
		{name: "accepts plain RemoteAddr IP", remoteAddr: "192.0.2.99", expected: "192.0.2.99"},
		{name: "returns empty for invalid values", xff: "invalid", xRealIP: "still-invalid", remoteAddr: "not-an-ip", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/sso/token", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			got := extractClientIP(req)
			if got != tt.expected {
				t.Errorf("extractClientIP() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestTokenRequestDelayDuration(t *testing.T) {
	t.Run("returns zero when both bounds are zero", func(t *testing.T) {
		d := tokenRequestDelayDuration(TokenRequestDelayConfig{MinMS: 0, MaxMS: 0})
		if d != 0 {
			t.Fatalf("expected 0 delay, got: %v", d)
		}
	})

	t.Run("returns fixed delay when min equals max", func(t *testing.T) {
		d := tokenRequestDelayDuration(TokenRequestDelayConfig{MinMS: 250, MaxMS: 250})
		if d != 250*time.Millisecond {
			t.Fatalf("expected 250ms delay, got: %v", d)
		}
	})

	t.Run("returns delay inside configured range", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			d := tokenRequestDelayDuration(TokenRequestDelayConfig{MinMS: 10, MaxMS: 20})
			if d < 10*time.Millisecond || d > 20*time.Millisecond {
				t.Fatalf("expected delay between 10ms and 20ms, got: %v", d)
			}
		}
	})
}

func TestTokenHandler_UsesForwardedClientIP(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	if err := loadTestKey(); err != nil {
		t.Skipf("Could not load test key: %v", err)
		return
	}

	clientLookupMap = map[string]string{"mobile-test": "mobile"}
	audienceLookupMap = map[string][]string{"mobile-test": {"mobile-audience"}}
	ttlLookupMap = map[string]time.Duration{"mobile-test": 2 * time.Hour}
	appConfig.PublicHost = "http://localhost:8080"

	form := url.Values{}
	form.Set("client_id", "mobile-test")
	form.Set("grant_type", "client_credentials")
	form.Set("device_id", "device-1")

	req := httptest.NewRequest(http.MethodPost, "/sso/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.0.0.3")
	req.RemoteAddr = "10.0.0.3:45000"
	w := httptest.NewRecorder()

	tokenHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got: %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse JSON response: %v", err)
	}

	tokenString, ok := response["access_token"].(string)
	if !ok {
		t.Fatal("Expected access_token in response")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		keyMu.RLock()
		defer keyMu.RUnlock()
		return &currentKey.key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Failed to read claims")
	}

	if got := claims["client_ip"]; got != "203.0.113.50" {
		t.Errorf("Expected client_ip 203.0.113.50, got: %v", got)
	}
}

func TestGenerateJTI(t *testing.T) {
	now := time.Now()
	jti1 := generateJTI("client1", now)
	jti2 := generateJTI("client2", now)
	jti3 := generateJTI("client1", now)

	if jti1 == "" {
		t.Error("JTI should not be empty")
	}

	if !strings.HasPrefix(jti1, "jti_") {
		t.Errorf("JTI should have 'jti_' prefix, got: %s", jti1)
	}

	if jti1 == jti2 {
		t.Error("Different clients should produce different JTIs")
	}

	if jti1 != jti3 {
		t.Error("Same client and timestamp should produce same JTI (deterministic)")
	}
}

func TestTokenClaimsRFC7519Compliance(t *testing.T) {
	if err := loadTestKey(); err != nil {
		t.Skipf("Could not load test key: %v", err)
	}

	appConfig.PublicHost = "test.example.com"
	audienceLookupMap = make(map[string][]string)
	ttlLookupMap = make(map[string]time.Duration)
	clientLookupMap = make(map[string]string)
	originLookupMap = make(map[string][]string)

	audienceLookupMap["test-client"] = []string{"test-aud"}
	ttlLookupMap["test-client"] = time.Hour
	clientLookupMap["test-client"] = clientTypeWeb
	originLookupMap["test-client"] = []string{"https://example.com"}

	form := url.Values{
		"client_id":  {"test-client"},
		"grant_type": {"client_credentials"},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://example.com")

	w := httptest.NewRecorder()
	tokenHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got: %d, body: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	tokenStr, ok := response["access_token"].(string)
	if !ok {
		t.Fatal("access_token not found in response")
	}

	token, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		keyMu.RLock()
		defer keyMu.RUnlock()
		if currentKey == nil {
			return nil, errors.New("key not loaded")
		}
		return currentKey.key.Public(), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Failed to read claims")
	}

	// RFC 7519 required claims
	if _, exists := claims["iss"]; !exists {
		t.Error("Missing 'iss' claim (RFC 7519)")
	}
	if _, exists := claims["exp"]; !exists {
		t.Error("Missing 'exp' claim (RFC 7519)")
	}
	if _, exists := claims["iat"]; !exists {
		t.Error("Missing 'iat' claim (RFC 7519)")
	}
	if _, exists := claims["jti"]; !exists {
		t.Error("Missing 'jti' claim (RFC 7519)")
	}

	// Verify iat is valid timestamp
	if iat, ok := claims["iat"].(float64); ok {
		if iat <= 0 {
			t.Error("'iat' claim should be a positive Unix timestamp")
		}
	} else {
		t.Error("'iat' claim should be a number")
	}

	// Verify jti format
	if jti, ok := claims["jti"].(string); ok {
		if !strings.HasPrefix(jti, "jti_") {
			t.Errorf("'jti' claim should start with 'jti_', got: %s", jti)
		}
	} else {
		t.Error("'jti' claim should be a string")
	}
}

// TestRFC7519RFC6749Compliance validates comprehensive RFC compliance:
// - RFC 7519: JWT standard claims and structure
// - RFC 6749: OAuth2 token response and error response format
// - HTTP headers: Cache-Control, Pragma, WWW-Authenticate
func TestRFC7519RFC6749Compliance(t *testing.T) {
	if err := loadTestKey(); err != nil {
		t.Skipf("Could not load test key: %v", err)
	}

	appConfig.PublicHost = "https://idp.example.com"
	appConfig.HideErrorDescription = false
	audienceLookupMap = make(map[string][]string)
	ttlLookupMap = make(map[string]time.Duration)
	clientLookupMap = make(map[string]string)
	originLookupMap = make(map[string][]string)

	audienceLookupMap["rfc-test"] = []string{"test-audience"}
	ttlLookupMap["rfc-test"] = 1 * time.Hour
	clientLookupMap["rfc-test"] = clientTypeWeb
	originLookupMap["rfc-test"] = []string{"https://example.com"}

	form := url.Values{
		"client_id":  {"rfc-test"},
		"grant_type": {"client_credentials"},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://example.com")
	req.RemoteAddr = "192.168.1.100:12345"

	w := httptest.NewRecorder()
	tokenHandler(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got: %d, body: %s", w.Code, w.Body.String())
	}

	// RFC 6749: Check response headers
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("RFC 6749: Missing 'application/json' Content-Type, got: %s", ct)
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("RFC 6749: Cache-Control should be 'no-store', got: %s", cc)
	}
	if pragma := w.Header().Get("Pragma"); pragma != "no-cache" {
		t.Errorf("RFC 6749: Pragma should be 'no-cache', got: %s", pragma)
	}

	var response map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	// RFC 6749: Check response fields
	if _, exists := response["access_token"]; !exists {
		t.Error("RFC 6749: Missing 'access_token' in response")
	}
	if _, exists := response["token_type"]; !exists {
		t.Error("RFC 6749: Missing 'token_type' in response")
	}
	if tokenType, ok := response["token_type"].(string); ok && tokenType != "Bearer" {
		t.Errorf("RFC 6749: token_type should be 'Bearer', got: %s", tokenType)
	}
	if expiresIn, ok := response["expires_in"].(float64); !ok || expiresIn != 3600 {
		t.Errorf("RFC 6749: expires_in should be 3600 seconds, got: %v", expiresIn)
	}

	tokenStr, ok := response["access_token"].(string)
	if !ok {
		t.Fatal("RFC 6749: access_token not a string")
	}

	// Parse and validate JWT
	token, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		keyMu.RLock()
		defer keyMu.RUnlock()
		if currentKey == nil {
			return nil, errors.New("key not loaded")
		}
		return currentKey.key.Public(), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("RFC 7519: Failed to read claims")
	}

	// RFC 7519: Validate required claims
	requiredClaims := []string{"iss", "exp", "iat", "sub", "aud"}
	for _, claim := range requiredClaims {
		if _, exists := claims[claim]; !exists {
			t.Errorf("RFC 7519: Missing required claim '%s'", claim)
		}
	}

	// RFC 7519: Validate iat (Issued At)
	iat, ok := claims["iat"].(float64)
	if !ok {
		t.Error("RFC 7519: 'iat' must be a number (Unix timestamp)")
	}
	if iat <= 0 {
		t.Error("RFC 7519: 'iat' must be a positive Unix timestamp")
	}

	// RFC 7519: Validate exp (Expiration)
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Error("RFC 7519: 'exp' must be a number")
	}
	if exp <= iat {
		t.Error("RFC 7519: 'exp' must be greater than 'iat'")
	}

	// RFC 7519: Validate jti (JWT ID)
	jti, ok := claims["jti"].(string)
	if !ok {
		t.Error("RFC 7519: 'jti' must be a string")
	}
	if !strings.HasPrefix(jti, "jti_") {
		t.Errorf("RFC 7519: 'jti' should have 'jti_' prefix for uniqueness, got: %s", jti)
	}
	if len(jti) < 10 {
		t.Errorf("RFC 7519: 'jti' too short, got: %s", jti)
	}

	// RFC 7519: Validate iss (Issuer)
	iss, ok := claims["iss"].(string)
	if !ok {
		t.Error("RFC 7519: 'iss' must be a string")
	}
	if !strings.Contains(iss, "idp.example.com") {
		t.Errorf("RFC 7519: 'iss' should match public host, got: %s", iss)
	}

	// RFC 7519: Validate aud (Audience)
	aud := claims["aud"]
	if aud == nil {
		t.Error("RFC 7519: 'aud' claim missing")
	}

	// RFC 7519: Validate sub (Subject)
	sub, ok := claims["sub"].(string)
	if !ok {
		t.Error("RFC 7519: 'sub' must be a string")
	}
	if !strings.HasPrefix(sub, "anon-") {
		t.Errorf("RFC 7519: 'sub' should start with 'anon-', got: %s", sub)
	}

	// RFC 7519: Header validation
	if token.Header["alg"] != "ES256" {
		t.Errorf("RFC 7519: Algorithm should be ES256, got: %v", token.Header["alg"])
	}
	if token.Header["kid"] == nil {
		t.Error("RFC 7519: Missing 'kid' header (Key ID)")
	}
	if token.Header["jku"] == nil {
		t.Error("RFC 7519: Missing 'jku' header (JWKS URL)")
	}
}

// TestOAuth2ErrorResponseFormat validates RFC 6749 error response format
func TestOAuth2ErrorResponseFormat(t *testing.T) {
	appConfig.HideErrorDescription = false
	appConfig.PublicHost = "https://idp.example.com"
	clientLookupMap = make(map[string]string)

	// Test invalid_request error
	form := url.Values{
		"grant_type": {"client_credentials"},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	tokenHandler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got: %d", w.Code)
	}

	// Check RFC 6749 error response headers
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("RFC 6749: Error response missing Cache-Control: no-store, got: %s", cc)
	}
	if pragma := w.Header().Get("Pragma"); pragma != "no-cache" {
		t.Errorf("RFC 6749: Error response missing Pragma: no-cache, got: %s", pragma)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("RFC 6749: Error response missing application/json, got: %s", ct)
	}

	var errResp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}

	if errResp["error"] == "" {
		t.Error("RFC 6749: Error response missing 'error' field")
	}
	if errResp["error_description"] == "" {
		t.Error("RFC 6749: Error response missing 'error_description' (hideErrorDescription=false)")
	}
}

// TestOAuth2InvalidClientAuthentication validates RFC 6749 invalid_client error
func TestOAuth2InvalidClientAuthentication(t *testing.T) {
	appConfig.HideErrorDescription = false
	appConfig.PublicHost = "https://idp.example.com"
	clientLookupMap = make(map[string]string)

	form := url.Values{
		"client_id":  {"unknown-client"},
		"grant_type": {"client_credentials"},
	}
	req := httptest.NewRequest(http.MethodPost, "/sso/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	w := httptest.NewRecorder()
	tokenHandler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("RFC 6749: Expected 401 for invalid_client, got: %d", w.Code)
	}

	// Check WWW-Authenticate header for invalid_client (RFC 2617)
	if auth := w.Header().Get("WWW-Authenticate"); !strings.Contains(auth, "invalid_client") {
		t.Errorf("RFC 2617: Missing WWW-Authenticate header for invalid_client, got: %s", auth)
	}

	var errResp map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("Failed to parse error response: %v", err)
	}

	if errResp["error"] != "invalid_client" {
		t.Errorf("RFC 6749: Expected error='invalid_client', got: %s", errResp["error"])
	}
}

// TestOAuthMetadataHandler tests RFC 8414 OAuth 2.0 Authorization Server Metadata
func TestOAuthMetadataHandler(t *testing.T) {
	appConfig.PublicHost = "https://idp.example.com"

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	oauthMetadataHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got: %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected Content-Type application/json, got: %s", contentType)
	}

	// RFC 8414: Check Cache-Control header
	cacheControl := w.Header().Get("Cache-Control")
	if cacheControl == "" {
		t.Errorf("Expected Cache-Control header for metadata caching")
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("Failed to parse metadata response: %v", err)
	}

	// RFC 8414: Required metadata fields
	requiredFields := []string{
		"issuer",
		"token_endpoint",
		"jwks_uri",
		"grant_types_supported",
		"token_endpoint_auth_methods_supported",
	}

	for _, field := range requiredFields {
		if _, exists := metadata[field]; !exists {
			t.Errorf("RFC 8414: Missing required field '%s'", field)
		}
	}

	// Verify issuer format
	if issuer, ok := metadata["issuer"].(string); ok {
		if !strings.Contains(issuer, "idp.example.com") {
			t.Errorf("issuer should match public host, got: %s", issuer)
		}
	} else {
		t.Error("issuer should be a string")
	}

	// Verify token_endpoint
	if tokenEndpoint, ok := metadata["token_endpoint"].(string); ok {
		if !strings.Contains(tokenEndpoint, "/sso/token") {
			t.Errorf("token_endpoint should contain /sso/token, got: %s", tokenEndpoint)
		}
	} else {
		t.Error("token_endpoint should be a string")
	}

	// Verify jwks_uri
	if jwksUri, ok := metadata["jwks_uri"].(string); ok {
		if !strings.Contains(jwksUri, "/.well-known/jwks.json") {
			t.Errorf("jwks_uri should contain /.well-known/jwks.json, got: %s", jwksUri)
		}
	} else {
		t.Error("jwks_uri should be a string")
	}

	// Verify grant_types_supported
	if grantTypes, ok := metadata["grant_types_supported"].([]interface{}); ok {
		found := false
		for _, gt := range grantTypes {
			if gt == "client_credentials" {
				found = true
				break
			}
		}
		if !found {
			t.Error("grant_types_supported should contain 'client_credentials'")
		}
	} else {
		t.Error("grant_types_supported should be an array")
	}

	// Verify token_endpoint_auth_methods_supported
	if authMethods, ok := metadata["token_endpoint_auth_methods_supported"].([]interface{}); ok {
		if len(authMethods) == 0 {
			t.Error("token_endpoint_auth_methods_supported should not be empty")
		}
	} else {
		t.Error("token_endpoint_auth_methods_supported should be an array")
	}
}
