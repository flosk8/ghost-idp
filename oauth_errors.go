package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

// writeOAuthError writes RFC-compliant OAuth2 error responses for the token endpoint.
// Includes Cache-Control/Pragma headers and optional WWW-Authenticate for invalid_client.
// error_description is omitted if hideErrorDescription is true (for security).
func writeOAuthError(w http.ResponseWriter, status int, code, description string, hideErrorDescription bool) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if status == http.StatusUnauthorized && code == "invalid_client" {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_client"`)
	}
	w.WriteHeader(status)

	response := map[string]string{"error": code}
	if !hideErrorDescription && strings.TrimSpace(description) != "" {
		response["error_description"] = description
	}
	_ = json.NewEncoder(w).Encode(response)
}
