package main

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// generateJTI creates a unique JWT ID (jti claim) using client_id and timestamp
func generateJTI(clientID string, t time.Time) string {
	hash := sha256.New()
	hash.Write([]byte(clientID + t.String()))
	return "jti_" + hex.EncodeToString(hash.Sum(nil))[:20]
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func readyHandler(w http.ResponseWriter, _ *http.Request) {
	keyMu.RLock()
	ready := currentKey != nil
	keyMu.RUnlock()

	if !ready {
		writeJSONError(w, http.StatusServiceUnavailable, "not ready")
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

func writeJSONError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	// Public CORS access allows tools like jwt.io to fetch the public key automatically.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	keyMu.RLock()
	defer keyMu.RUnlock()

	if currentKey == nil {
		appLogger.Error("JWKS request received but signing key not loaded.")
		writeJSONError(w, http.StatusInternalServerError, "Key not loaded")
		return
	}

	keys := []map[string]string{jwkFromEntry(currentKey)}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{"keys": keys}); err != nil {
		appLogger.Error("Failed to encode JWKS response: %v", err)
	}
}

func jwkFromEntry(e *keyEntry) map[string]string {
	pub := e.key.Public().(*ecdsa.PublicKey)
	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"use": "sig",
		"kid": e.kid,
		"x":   base64.RawURLEncoding.EncodeToString(pub.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(pub.Y.Bytes()),
		"alg": "ES256",
	}
}

func formatHost(host string) string {
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		return "https://" + host
	}
	return host
}

func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for _, part := range strings.Split(xff, ",") {
			ip := strings.TrimSpace(part)
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}

	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" && net.ParseIP(xri) != nil {
		return xri
	}

	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil && net.ParseIP(host) != nil {
		return host
	}

	if ip := strings.TrimSpace(r.RemoteAddr); net.ParseIP(ip) != nil {
		return ip
	}

	return ""
}

func isOriginAllowed(origin string, allowedOrigins []string) bool {
	for _, ao := range allowedOrigins {
		if ao == "*" || ao == origin {
			return true
		}
	}
	return false
}

func extractCookieDomain(host string) string {
	domain := strings.Split(strings.Replace(host, "https://", "", 1), "/")[0]
	if strings.HasPrefix(domain, "localhost") {
		return "localhost"
	}
	parts := strings.Split(domain, ".")
	if len(parts) > 2 {
		return "." + parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return domain
}

func tokenRequestDelayDuration(cfg TokenRequestDelayConfig) time.Duration {
	minMS := cfg.MinMS
	maxMS := cfg.MaxMS

	if minMS < 0 {
		minMS = 0
	}
	if maxMS < 0 {
		maxMS = 0
	}
	if minMS > maxMS {
		minMS, maxMS = maxMS, minMS
	}
	if minMS == 0 && maxMS == 0 {
		return 0
	}
	if minMS == maxMS {
		return time.Duration(minMS) * time.Millisecond
	}

	span := maxMS - minMS + 1
	randomIndex, err := crand.Int(crand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return time.Duration(minMS) * time.Millisecond
	}

	return time.Duration(minMS+int(randomIndex.Int64())) * time.Millisecond
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		appLogger.Warn("Token endpoint called with invalid method: %s", r.Method)
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method must be POST", appConfig.HideErrorDescription)
		return
	}

	contentType := strings.TrimSpace(r.Header.Get("Content-Type"))
	if contentType == "" || (!strings.HasPrefix(contentType, "application/x-www-form-urlencoded") && contentType != "application/x-www-form-urlencoded") {
		appLogger.Warn("Token request with invalid Content-Type: %s", contentType)
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "content-type must be application/x-www-form-urlencoded", appConfig.HideErrorDescription)
		return
	}

	if err := r.ParseForm(); err != nil {
		appLogger.Error("Failed to parse form data: %v", err)
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "failed to parse form body", appConfig.HideErrorDescription)
		return
	}

	clientID := r.FormValue("client_id")
	if clientID == "" {
		appLogger.Warn("Token request missing 'client_id' parameter in form data.")
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required", appConfig.HideErrorDescription)
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType == "" {
		appLogger.Warn("Token request missing 'grant_type' parameter in form_data.")
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "grant_type is required", appConfig.HideErrorDescription)
		return
	}
	if grantType != "client_credentials" {
		appLogger.Warn("Invalid grant_type provided: %s", grantType)
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be client_credentials", appConfig.HideErrorDescription)
		return
	}

	clientType, ok := clientLookupMap[clientID]
	if !ok {
		appLogger.Warn("Invalid client_id provided: %s", clientID)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed", appConfig.HideErrorDescription)
		return
	}

	var deviceID string
	if clientType == clientTypeMobile {
		deviceID = strings.TrimSpace(r.FormValue("device_id"))
		if deviceID == "" {
			appLogger.Warn("Token request from mobile client '%s' missing 'device_id' form parameter.", clientID)
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "device_id is required", appConfig.HideErrorDescription)
			return
		}
		appLogger.Info("Processing token request for mobile client: %s with device ID: %s", clientID, deviceID)
	} else if clientType == clientTypeWeb {
		appLogger.Info("Processing token request for web client: %s", clientID)
		origin := r.Header.Get("Origin")
		if origin == "" {
			appLogger.Warn("Token request from web client '%s' missing 'Origin' header.", clientID)
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Origin header is required for web clients", appConfig.HideErrorDescription)
			return
		}

		allowedOrigins, originsFound := originLookupMap[clientID]
		if !originsFound || len(allowedOrigins) == 0 {
			appLogger.Warn("No allowed origins configured for web client '%s'. Denying request from origin '%s'.", clientID, origin)
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client not configured for origin validation", appConfig.HideErrorDescription)
			return
		}

		if !isOriginAllowed(origin, allowedOrigins) {
			appLogger.Warn("Origin '%s' not allowed for client '%s'. Allowed: %v", origin, clientID, allowedOrigins)
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "origin not allowed", appConfig.HideErrorDescription)
			return
		}
		appLogger.Info("Origin '%s' validated successfully for client '%s'.", origin, clientID)
	}

	attestationResult, err := verifyRequestAttestation(r, clientID, clientType)
	if err != nil {
		status := http.StatusBadRequest
		code := "invalid_request"
		if errors.Is(err, ErrAttestationMissing) {
			status = http.StatusBadRequest
			code = "invalid_request"
		} else {
			code = "invalid_grant"
		}
		appLogger.Warn("Attestation failed for client '%s': %v", clientID, err)
		writeOAuthError(w, status, code, err.Error(), appConfig.HideErrorDescription)
		return
	}
	_ = attestationResult

	if delay := tokenRequestDelayDuration(appConfig.Token.TokenRequestDelay); delay > 0 {
		time.Sleep(delay)
	}

	keyMu.RLock()
	defer keyMu.RUnlock()

	if currentKey == nil {
		appLogger.Warn("Token request for client '%s' received, but signing key is not loaded.", clientID)
		writeOAuthError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable", appConfig.HideErrorDescription)
		return
	}

	var audience []string
	if aud, found := audienceLookupMap[clientID]; found && len(aud) > 0 {
		audience = aud
	} else {
		audience = []string{clientID}
	}

	tokenTTL, ttlFound := ttlLookupMap[clientID]
	if !ttlFound {
		// Should never happen if initClientLookup ran correctly, but guard against config errors.
		appLogger.Error("TTL not found for client '%s'. This indicates a configuration error.", clientID)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal server error", appConfig.HideErrorDescription)
		return
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       formatHost(appConfig.PublicHost),
		"sub":       "anon-" + now.Format("20060102150405"),
		"role":      "guest",
		"aud":       audience,
		"client_id": clientID,
		"iat":       now.Unix(),
		"exp":       now.Add(tokenTTL).Unix(),
		"jti":       generateJTI(clientID, now),
	}
	if deviceID != "" {
		claims["device_id"] = deviceID
	}

	if clientIP := extractClientIP(r); clientIP != "" {
		claims["client_ip"] = clientIP
	} else {
		appLogger.Warn("Could not determine client IP from request headers/RemoteAddr. RemoteAddr='%s'", r.RemoteAddr)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = currentKey.kid
	token.Header["jku"] = fmt.Sprintf("%s/.well-known/jwks.json", formatHost(appConfig.PublicHost))

	tokenString, err := token.SignedString(currentKey.key)
	if err != nil {
		appLogger.Error("Failed to sign token for client '%s': %v", clientID, err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "internal server error", appConfig.HideErrorDescription)
		return
	}

	if clientType == clientTypeWeb {
		http.SetCookie(w, &http.Cookie{
			Name:     "anon_token",
			Value:    tokenString,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
			Domain:   extractCookieDomain(appConfig.PublicHost),
		})
	}

	response := map[string]interface{}{
		"access_token": tokenString,
		"expires_in":   int(tokenTTL.Seconds()),
		"token_type":   "Bearer",
		"scope":        "guest",
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		appLogger.Error("Failed to encode token response for client '%s': %v", clientID, err)
	}
}

// oauthMetadataHandler returns OAuth 2.0 Authorization Server Metadata (RFC 8414)
// Endpoint: GET /.well-known/oauth-authorization-server
func oauthMetadataHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")

	publicHost := formatHost(appConfig.PublicHost)
	metadata := map[string]interface{}{
		// RFC 8414 Required Claims
		"issuer":                                publicHost,
		"token_endpoint":                        publicHost + "/sso/token",
		"jwks_uri":                              publicHost + "/.well-known/jwks.json",
		"token_endpoint_auth_methods_supported": []string{"none"},

		// RFC 8414 Recommended Claims
		"grant_types_supported": []string{
			"client_credentials",
		},

		// Additional metadata for transparency
		"response_types_supported": []string{
			"token",
		},
		"token_type_supported":  "Bearer",
		"service_documentation": "https://github.com/ndrde/ghost-idp",
	}

	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		appLogger.Error("Failed to encode OAuth metadata response: %v", err)
	}
}
