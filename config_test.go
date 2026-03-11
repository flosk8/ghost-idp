package main

import (
	"os"
	"testing"
	"time"
)

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{
			name:     "2 hours",
			input:    "2h",
			expected: 2 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "24 hours",
			input:    "24h",
			expected: 24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "1 day",
			input:    "1d",
			expected: 24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "30 days",
			input:    "30d",
			expected: 30 * 24 * time.Hour,
			wantErr:  false,
		},
		{
			name:     "invalid format - no unit",
			input:    "5",
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "invalid format - empty",
			input:    "",
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "invalid format - unknown unit",
			input:    "5m",
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "invalid format - non-numeric",
			input:    "abch",
			expected: 0,
			wantErr:  true,
		},
		{
			name:     "with whitespace",
			input:    " 3h ",
			expected: 3 * time.Hour,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseDuration(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("parseDuration(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		fallback string
		setEnv   bool
		envValue string
		expected string
	}{
		{
			name:     "env var exists",
			key:      "TEST_VAR_EXISTS",
			fallback: "default",
			setEnv:   true,
			envValue: "custom_value",
			expected: "custom_value",
		},
		{
			name:     "env var does not exist",
			key:      "TEST_VAR_NOT_EXISTS",
			fallback: "default_value",
			setEnv:   false,
			expected: "default_value",
		},
		{
			name:     "empty env var",
			key:      "TEST_VAR_EMPTY",
			fallback: "default",
			setEnv:   true,
			envValue: "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				if err := os.Setenv(tt.key, tt.envValue); err != nil {
					t.Fatalf("Failed to set env var: %v", err)
				}
				defer func() {
					_ = os.Unsetenv(tt.key)
				}()
			}

			result := getEnv(tt.key, tt.fallback)
			if result != tt.expected {
				t.Errorf("getEnv(%q, %q) = %q, want %q", tt.key, tt.fallback, result, tt.expected)
			}
		})
	}
}

func TestLoadConfig(t *testing.T) {
	// Save original appLogger and restore after test
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()

	// Use a text logger for tests
	appLogger = &TextLogger{}

	t.Run("non-existent config file", func(t *testing.T) {
		// Reset config
		appConfig = AppConfig{}

		err := LoadConfig("non_existent_config.yaml")
		// Should not return an error - uses defaults and env vars
		if err != nil {
			t.Errorf("LoadConfig with non-existent file should not error, got: %v", err)
		}

		// Should have default values
		if appConfig.KeyPath != "/etc/ghost-idp/certs/tls.key" {
			t.Errorf("Expected default KeyPath, got: %s", appConfig.KeyPath)
		}
		if appConfig.PublicHost != "http://localhost:8080" {
			t.Errorf("Expected default PublicHost, got: %s", appConfig.PublicHost)
		}
		if appConfig.Token.TTL != "2h" {
			t.Errorf("Expected default TTL, got: %s", appConfig.Token.TTL)
		}
		if appConfig.Attestation.Enabled {
			t.Error("Expected attestation to be disabled by default")
		}
		if appConfig.Attestation.HeaderName != "X-Device-Id" {
			t.Errorf("Expected default attestation header, got: %s", appConfig.Attestation.HeaderName)
		}
		if appConfig.Attestation.Provider != "noop" {
			t.Errorf("Expected default attestation provider noop, got: %s", appConfig.Attestation.Provider)
		}
		if appConfig.Attestation.MaxAgeSeconds != 60 {
			t.Errorf("Expected default attestation max age 60, got: %d", appConfig.Attestation.MaxAgeSeconds)
		}
	})

	t.Run("env var overrides", func(t *testing.T) {
		// Reset config
		appConfig = AppConfig{}

		if err := os.Setenv("JWT_KEY_PATH", "/custom/key/path"); err != nil {
			t.Fatalf("Failed to set env var: %v", err)
		}
		if err := os.Setenv("PUBLIC_HOST", "https://custom.host"); err != nil {
			t.Fatalf("Failed to set env var: %v", err)
		}
		if err := os.Setenv("TOKEN_TTL", "5h"); err != nil {
			t.Fatalf("Failed to set env var: %v", err)
		}
		if err := os.Setenv("ATTESTATION_ENABLED", "true"); err != nil {
			t.Fatalf("Failed to set env var: %v", err)
		}
		if err := os.Setenv("ATTESTATION_REQUIRED_FOR", "mobile,web"); err != nil {
			t.Fatalf("Failed to set env var: %v", err)
		}
		if err := os.Setenv("ATTESTATION_HEADER", "X-Attestation"); err != nil {
			t.Fatalf("Failed to set env var: %v", err)
		}
		if err := os.Setenv("ATTESTATION_PROVIDER", "stub"); err != nil {
			t.Fatalf("Failed to set env var: %v", err)
		}
		if err := os.Setenv("ATTESTATION_MAX_AGE_SECONDS", "120"); err != nil {
			t.Fatalf("Failed to set env var: %v", err)
		}
		defer func() {
			_ = os.Unsetenv("JWT_KEY_PATH")
			_ = os.Unsetenv("PUBLIC_HOST")
			_ = os.Unsetenv("TOKEN_TTL")
			_ = os.Unsetenv("ATTESTATION_ENABLED")
			_ = os.Unsetenv("ATTESTATION_REQUIRED_FOR")
			_ = os.Unsetenv("ATTESTATION_HEADER")
			_ = os.Unsetenv("ATTESTATION_PROVIDER")
			_ = os.Unsetenv("ATTESTATION_MAX_AGE_SECONDS")
		}()

		err := LoadConfig("non_existent_config.yaml")
		if err != nil {
			t.Errorf("LoadConfig should not error, got: %v", err)
		}

		if appConfig.KeyPath != "/custom/key/path" {
			t.Errorf("Expected KeyPath from env var, got: %s", appConfig.KeyPath)
		}
		if appConfig.PublicHost != "https://custom.host" {
			t.Errorf("Expected PublicHost from env var, got: %s", appConfig.PublicHost)
		}
		if appConfig.Token.TTL != "5h" {
			t.Errorf("Expected TTL from env var, got: %s", appConfig.Token.TTL)
		}
		if !appConfig.Attestation.Enabled {
			t.Error("Expected attestation enabled from env var")
		}
		if len(appConfig.Attestation.RequiredFor) != 2 {
			t.Errorf("Expected 2 requiredFor entries, got: %d", len(appConfig.Attestation.RequiredFor))
		}
		if appConfig.Attestation.HeaderName != "X-Attestation" {
			t.Errorf("Expected attestation header from env var, got: %s", appConfig.Attestation.HeaderName)
		}
		if appConfig.Attestation.Provider != "stub" {
			t.Errorf("Expected attestation provider from env var, got: %s", appConfig.Attestation.Provider)
		}
		if appConfig.Attestation.MaxAgeSeconds != 120 {
			t.Errorf("Expected attestation max age from env var, got: %d", appConfig.Attestation.MaxAgeSeconds)
		}
	})
}

func TestInitClientLookup(t *testing.T) {
	// Save original appLogger and restore after test
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	// Setup test config
	appConfig = AppConfig{
		Token: TokenConfig{
			TTL: "2h",
			Config: map[string]TokenProfile{
				"dev": {
					TTL:      "3h",
					Audience: []string{"test-dev", "test-qa"},
				},
				"prod": {
					TTL:      "4h",
					Audience: []string{"test-prod"},
				},
			},
		},
		Clients: Clients{
			Web: []Client{
				{
					Name:           "web-client-1",
					Config:         "dev",
					AllowedOrigins: []string{"https://example.com"},
				},
			},
			Mobile: []Client{
				{
					Name:       "mobile-client-1",
					Config:     "prod",
					HMACSecret: "super-secret",
				},
			},
		},
	}

	initClientLookup()

	t.Run("client lookup map", func(t *testing.T) {
		if clientLookupMap["web-client-1"] != "web" {
			t.Errorf("Expected web-client-1 to be 'web', got: %s", clientLookupMap["web-client-1"])
		}
		if clientLookupMap["mobile-client-1"] != "mobile" {
			t.Errorf("Expected mobile-client-1 to be 'mobile', got: %s", clientLookupMap["mobile-client-1"])
		}
	})

	t.Run("origin lookup map", func(t *testing.T) {
		origins, exists := originLookupMap["web-client-1"]
		if !exists {
			t.Error("Expected web-client-1 to have origins")
		}
		if len(origins) != 1 || origins[0] != "https://example.com" {
			t.Errorf("Expected origins [https://example.com], got: %v", origins)
		}
	})

	t.Run("audience lookup map", func(t *testing.T) {
		audience, exists := audienceLookupMap["web-client-1"]
		if !exists {
			t.Error("Expected web-client-1 to have audience")
		}
		if len(audience) != 2 {
			t.Errorf("Expected 2 audiences, got: %d", len(audience))
		}
	})

	t.Run("ttl lookup map", func(t *testing.T) {
		ttl, exists := ttlLookupMap["web-client-1"]
		if !exists {
			t.Error("Expected web-client-1 to have TTL")
		}
		if ttl != 3*time.Hour {
			t.Errorf("Expected TTL 3h, got: %v", ttl)
		}

		ttl, exists = ttlLookupMap["mobile-client-1"]
		if !exists {
			t.Error("Expected mobile-client-1 to have TTL")
		}
		if ttl != 4*time.Hour {
			t.Errorf("Expected TTL 4h, got: %v", ttl)
		}
	})

	t.Run("hmac secret lookup map", func(t *testing.T) {
		secret, exists := hmacSecretLookupMap["mobile-client-1"]
		if !exists {
			t.Error("Expected mobile-client-1 to have hmac secret")
		}
		if secret != "super-secret" {
			t.Errorf("Expected hmac secret super-secret, got: %s", secret)
		}
	})

	t.Run("client count", func(t *testing.T) {
		if len(clientLookupMap) != 2 {
			t.Errorf("Expected 2 clients, got: %d", len(clientLookupMap))
		}
	})
}

func TestClientConfig(t *testing.T) {
	t.Run("Client struct", func(t *testing.T) {
		client := Client{
			Name:           "test-client",
			Config:         "dev",
			AllowedOrigins: []string{"https://test.com"},
		}

		if client.Name != "test-client" {
			t.Errorf("Expected Name 'test-client', got: %s", client.Name)
		}
		if client.Config != "dev" {
			t.Errorf("Expected Config 'dev', got: %s", client.Config)
		}
		if len(client.AllowedOrigins) != 1 {
			t.Errorf("Expected 1 origin, got: %d", len(client.AllowedOrigins))
		}
	})

	t.Run("TokenProfile struct", func(t *testing.T) {
		profile := TokenProfile{
			TTL:      "2h",
			Audience: []string{"aud1", "aud2"},
		}

		if profile.TTL != "2h" {
			t.Errorf("Expected TTL '2h', got: %s", profile.TTL)
		}
		if len(profile.Audience) != 2 {
			t.Errorf("Expected 2 audiences, got: %d", len(profile.Audience))
		}
	})
}
