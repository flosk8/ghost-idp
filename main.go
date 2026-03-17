package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var appLogger Logger = &TextLogger{}

func main() {
	if err := LoadConfig("config.yaml"); err != nil {
		appLogger.Fatal("Error loading configuration: %v", err)
	}

	if getEnv("LOG_FORMAT", "text") == "json" {
		appLogger = &JSONLogger{}
	} else {
		appLogger = &TextLogger{}
	}
	initAttestationProvider()

	initClientLookup()

	if err := loadKey(); err != nil {
		appLogger.Warn("Key could not be loaded (%v). Waiting for watcher or file...", err)
	}

	go watchKeyRotation()

	r := chi.NewRouter()
	r.Use(requestLoggerSkippingProbes)
	r.Use(middleware.Recoverer)

	r.Get("/healthz", healthHandler)
	r.Get("/readyz", readyHandler)
	r.Get("/.well-known/jwks.json", jwksHandler)
	r.Options("/.well-known/jwks.json", jwksHandler)
	r.Get("/.well-known/oauth-authorization-server", oauthMetadataHandler)
	r.Post("/sso/token", tokenHandler)

	appLogger.Info("Ghost-IdP (ECDSA) running on port 8080...")
	appLogger.Fatal("%v", http.ListenAndServe(":8080", r))
}
