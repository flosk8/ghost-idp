package main

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/base64"
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
	if err := r.ParseForm(); err != nil {
		appLogger.Error("Failed to parse form data: %v", err)
		writeJSONError(w, http.StatusBadRequest, "Bad Request")
		return
	}

	clientID := r.FormValue("client_id")
	if clientID == "" {
		appLogger.Warn("Token request missing 'client_id' parameter in form data.")
		writeJSONError(w, http.StatusBadRequest, "client_id is required")
		return
	}

	grantType := r.FormValue("grant_type")
	if grantType == "" {
		appLogger.Warn("Token request missing 'grant_type' parameter in form_data.")
		writeJSONError(w, http.StatusBadRequest, "grant_type is required")
		return
	}
	if grantType != "client_credentials" {
		appLogger.Warn("Invalid grant_type provided: %s", grantType)
		writeJSONError(w, http.StatusBadRequest, "unsupported_grant_type")
		return
	}

	clientType, ok := clientLookupMap[clientID]
	if !ok {
		appLogger.Warn("Invalid client_id provided: %s", clientID)
		writeJSONError(w, http.StatusForbidden, "Invalid client_id")
		return
	}

	var deviceID string
	if clientType == clientTypeMobile {
		deviceID = strings.TrimSpace(r.FormValue("device_id"))
		if deviceID == "" {
			appLogger.Warn("Token request from mobile client '%s' missing 'device_id' form parameter.", clientID)
			writeJSONError(w, http.StatusBadRequest, "device_id form parameter is required for mobile clients")
			return
		}
		appLogger.Info("Processing token request for mobile client: %s with device ID: %s", clientID, deviceID)
	} else if clientType == clientTypeWeb {
		appLogger.Info("Processing token request for web client: %s", clientID)
		origin := r.Header.Get("Origin")
		if origin == "" {
			appLogger.Warn("Token request from web client '%s' missing 'Origin' header.", clientID)
			writeJSONError(w, http.StatusBadRequest, "Origin header is required for web clients")
			return
		}

		allowedOrigins, originsFound := originLookupMap[clientID]
		if !originsFound || len(allowedOrigins) == 0 {
			appLogger.Warn("No allowed origins configured for web client '%s'. Denying request from origin '%s'.", clientID, origin)
			writeJSONError(w, http.StatusForbidden, "Client not configured for origin validation")
			return
		}

		if !isOriginAllowed(origin, allowedOrigins) {
			appLogger.Warn("Origin '%s' not allowed for client '%s'. Allowed: %v", origin, clientID, allowedOrigins)
			writeJSONError(w, http.StatusForbidden, "Origin not allowed")
			return
		}
		appLogger.Info("Origin '%s' validated successfully for client '%s'.", origin, clientID)
	}

	attestationResult, err := verifyRequestAttestation(r, clientID, clientType)
	if err != nil {
		status := http.StatusForbidden
		if errors.Is(err, ErrAttestationMissing) {
			status = http.StatusBadRequest
		}
		appLogger.Warn("Attestation failed for client '%s': %v", clientID, err)
		writeJSONError(w, status, err.Error())
		return
	}

	if delay := tokenRequestDelayDuration(appConfig.Token.TokenRequestDelay); delay > 0 {
		time.Sleep(delay)
	}

	keyMu.RLock()
	defer keyMu.RUnlock()

	if currentKey == nil {
		appLogger.Warn("Token request for client '%s' received, but signing key is not loaded.", clientID)
		writeJSONError(w, http.StatusServiceUnavailable, "Identity Provider is starting up...")
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
		writeJSONError(w, http.StatusInternalServerError, "Internal Server Error")
		return
	}

	claims := jwt.MapClaims{
		"iss":       formatHost(appConfig.PublicHost),
		"sub":       "anon-" + time.Now().Format("20060102150405"),
		"role":      "guest",
		"aud":       audience,
		"client_id": clientID,
		"exp":       time.Now().Add(tokenTTL).Unix(),
	}
	if deviceID != "" {
		claims["device_id"] = deviceID
	}
	if attestationResult != nil {
		claims["attested"] = true
		if attestationResult.Level != "" {
			claims["attestation_level"] = attestationResult.Level
		}
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
		writeJSONError(w, http.StatusInternalServerError, "Internal Server Error")
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
	if err := json.NewEncoder(w).Encode(response); err != nil {
		appLogger.Error("Failed to encode token response for client '%s': %v", clientID, err)
	}
}
