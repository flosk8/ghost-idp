package main

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

var (
	// kid should be consistent so the router knows which key to use
	kid = "ghost-idp-ecdsa-v1"

	appLogger Logger = &TextLogger{} // Global logger instance with default fallback
)

func main() {

	// Load configuration from config.yaml
	if err := LoadConfig("config.yaml"); err != nil {
		appLogger.Fatal("Error loading configuration: %v", err)
	}

	// Re-initialize logger based on the loaded configuration
	if getEnv("LOG_FORMAT", "text") == "json" {
		appLogger = &JSONLogger{}
	} else {
		appLogger = &TextLogger{}
	}

	// Initialize the client lookup map
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
	r.Post("/token", tokenHandler)

	appLogger.Info("Ghost-IdP (ECDSA) running on port 8080...")
	appLogger.Fatal("%v", http.ListenAndServe(":8080", r)) // Use appLogger.Fatal here
}
