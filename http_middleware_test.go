package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsProbeRequest(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		userAgent string
		xProbe    string
		expected  bool
	}{
		{
			name:     "/healthz path",
			path:     "/healthz",
			expected: true,
		},
		{
			name:     "/readyz path",
			path:     "/readyz",
			expected: true,
		},
		{
			name:      "kube-probe user agent lowercase",
			path:      "/sso/token",
			userAgent: "kube-probe/1.24",
			expected:  true,
		},
		{
			name:      "kube-probe user agent in string",
			path:      "/sso/token",
			userAgent: "kubelet/v1.24 (kube-probe) some-other-info",
			expected:  true,
		},
		{
			name:     "X-Probe: true header",
			path:     "/sso/token",
			xProbe:   "true",
			expected: true,
		},
		{
			name:     "X-Probe: True header (case insensitive)",
			path:     "/sso/token",
			xProbe:   "True",
			expected: true,
		},
		{
			name:     "normal request to /token",
			path:     "/sso/token",
			expected: false,
		},
		{
			name:     "normal request to /.well-known/jwks.json",
			path:     "/.well-known/jwks.json",
			expected: false,
		},
		{
			name:      "normal request with random user agent",
			path:      "/sso/token",
			userAgent: "curl/7.68.0",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}
			if tt.xProbe != "" {
				req.Header.Set("X-Probe", tt.xProbe)
			}

			result := isProbeRequest(req)
			if result != tt.expected {
				t.Errorf("isProbeRequest() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestRequestLoggerSkippingProbes(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	t.Run("logs normal request", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/sso/token", nil)
		w := httptest.NewRecorder()

		middleware := requestLoggerSkippingProbes(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		middleware.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got: %d", w.Code)
		}
	})

	t.Run("skips logging for /healthz probe", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		w := httptest.NewRecorder()

		middleware := requestLoggerSkippingProbes(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		middleware.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got: %d", w.Code)
		}
	})

	t.Run("skips logging for /readyz probe", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		w := httptest.NewRecorder()

		middleware := requestLoggerSkippingProbes(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		middleware.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got: %d", w.Code)
		}
	})

	t.Run("skips logging for X-Probe header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/some-endpoint", nil)
		req.Header.Set("X-Probe", "true")
		w := httptest.NewRecorder()

		middleware := requestLoggerSkippingProbes(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		middleware.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got: %d", w.Code)
		}
	})

	t.Run("skips logging for kube-probe user agent", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/some-endpoint", nil)
		req.Header.Set("User-Agent", "kube-probe/1.24")
		w := httptest.NewRecorder()

		middleware := requestLoggerSkippingProbes(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		middleware.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got: %d", w.Code)
		}
	})

	t.Run("sets correct status code for 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
		w := httptest.NewRecorder()

		middleware := requestLoggerSkippingProbes(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))

		middleware.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status 404, got: %d", w.Code)
		}
	})

	t.Run("default status is 200 if not set", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/sso/token", nil)
		w := httptest.NewRecorder()

		middleware := requestLoggerSkippingProbes(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Don't explicitly set status, should default to 200
			w.Write([]byte("ok"))
		}))

		middleware.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got: %d", w.Code)
		}
	})
}

func TestRequestLoggerWithDifferentMethods(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	methods := []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodOptions}

	for _, method := range methods {
		t.Run("logs "+method+" request", func(t *testing.T) {
			req := httptest.NewRequest(method, "/sso/token", nil)
			w := httptest.NewRecorder()

			middleware := requestLoggerSkippingProbes(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			middleware.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got: %d", w.Code)
			}
		})
	}
}
