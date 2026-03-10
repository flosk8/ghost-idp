package main

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

func requestLoggerSkippingProbes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isProbeRequest(r) {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}

		appLogger.Info("%s %s -> %d (%s)", r.Method, r.URL.Path, status, time.Since(start).Truncate(time.Millisecond))
	})
}

func isProbeRequest(r *http.Request) bool {
	if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Probe"), "true") {
		return true
	}
	return strings.Contains(strings.ToLower(r.UserAgent()), "kube-probe")
}
