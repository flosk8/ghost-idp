package main

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	ready := signingKey != nil
	keyMu.RUnlock()

	if !ready {
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}

func jwksHandler(w http.ResponseWriter, _ *http.Request) {
	keyMu.RLock()
	defer keyMu.RUnlock()

	if signingKey == nil {
		appLogger.Error("JWKS request received but signing key not loaded.")
		http.Error(w, "Key not loaded", http.StatusInternalServerError)
		return
	}

	pub := signingKey.Public().(*ecdsa.PublicKey)
	x := base64.RawURLEncoding.EncodeToString(pub.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(pub.Y.Bytes())

	resp := map[string]interface{}{
		"keys": []map[string]string{{
			"kty": "EC",
			"crv": "P-256",
			"use": "sig",
			"kid": kid,
			"x":   x,
			"y":   y,
			"alg": "ES256",
		}},
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		appLogger.Error("Failed to encode JWKS response: %v", err)
	}
}

func formatHost(host string) string {
	if !strings.HasPrefix(host, "http://") && !strings.HasPrefix(host, "https://") {
		return "https://" + host
	}
	return host
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the form data for x-www-form-urlencoded
	if err := r.ParseForm(); err != nil {
		appLogger.Error("Failed to parse form data: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// 1. Get client_id from form data
	clientID := r.FormValue("client_id")
	if clientID == "" {
		appLogger.Warn("Token request missing 'client_id' parameter in form data.")
		http.Error(w, "client_id is required", http.StatusBadRequest)
		return
	}

	// 2. Validate grant_type
	grantType := r.FormValue("grant_type")
	if grantType == "" {
		appLogger.Warn("Token request missing 'grant_type' parameter in form_data.")
		http.Error(w, "grant_type is required", http.StatusBadRequest)
		return
	}
	if grantType != "client_credentials" {
		appLogger.Warn("Invalid grant_type provided: %s", grantType)
		http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
		return
	}

	// 3. Validate client_id and get client_type from the lookup map
	clientType, ok := clientLookupMap[clientID]
	if !ok {
		appLogger.Warn("Invalid client_id provided: %s", clientID)
		http.Error(w, "Invalid client_id", http.StatusForbidden)
		return
	}

	// 4. Additional checks based on client type
	var deviceID string
	if clientType == "mobile" {
		deviceID = r.FormValue("device_id")
		if deviceID == "" {
			appLogger.Warn("Token request from mobile client '%s' missing 'device_id' parameter.", clientID)
			http.Error(w, "device_id is required for mobile clients", http.StatusBadRequest)
			return
		}
		appLogger.Info("Processing token request for mobile client: %s with device ID: %s", clientID, deviceID)
	} else if clientType == "web" {
		appLogger.Info("Processing token request for web client: %s", clientID)
		// Validate Origin header for web clients
		origin := r.Header.Get("Origin")
		if origin == "" {
			appLogger.Warn("Token request from web client '%s' missing 'Origin' header.", clientID)
			http.Error(w, "Origin header is required for web clients", http.StatusBadRequest)
			return
		}

		allowedOrigins, originsFound := originLookupMap[clientID]
		if !originsFound || len(allowedOrigins) == 0 {
			appLogger.Warn("No allowed origins configured for web client '%s'. Denying request from origin '%s'.", clientID, origin)
			http.Error(w, "Client not configured for origin validation", http.StatusForbidden)
			return
		}

		isOriginAllowed := false
		for _, ao := range allowedOrigins {
			if ao == "*" {
				isOriginAllowed = true
				break
			}
			if ao == origin {
				isOriginAllowed = true
				break
			}
		}

		if !isOriginAllowed {
			appLogger.Warn("Origin '%s' not allowed for client '%s'. Allowed: %v", origin, clientID, allowedOrigins)
			http.Error(w, "Origin not allowed", http.StatusForbidden)
			return
		}
		appLogger.Info("Origin '%s' validated successfully for client '%s'.", origin, clientID)
	}

	// 5. Generate the token
	keyMu.RLock()
	defer keyMu.RUnlock()

	if signingKey == nil {
		appLogger.Warn("Token request for client '%s' received, but signing key is not loaded.", clientID)
		http.Error(w, "Identity Provider is starting up...", http.StatusServiceUnavailable)
		return
	}

	// Determine the audience
	var audience []string
	if aud, found := audienceLookupMap[clientID]; found && len(aud) > 0 {
		audience = aud
	} else {
		audience = []string{clientID} // Fallback to clientID if no audience is configured
	}

	// Determine the TTL
	tokenTTL, ttlFound := ttlLookupMap[clientID]
	if !ttlFound {
		// This should not happen if initClientLookup is correct, but as a safeguard:
		appLogger.Error("TTL not found for client '%s'. This indicates a configuration error.", clientID)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	claims := jwt.MapClaims{
		"iss":       formatHost(appConfig.PublicHost),
		"sub":       "anon-" + time.Now().Format("20060102150405"),
		"role":      "guest",
		"aud":       audience, // Use configured audience
		"client_id": clientID, // Explicit client_id claim
		"exp":       time.Now().Add(tokenTTL).Unix(),
	}
	if deviceID != "" {
		claims["device_id"] = deviceID
	}

	// Add client IP to claims
	if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		claims["client_ip"] = clientIP
	} else {
		appLogger.Warn("Could not parse client IP from RemoteAddr '%s': %v", r.RemoteAddr, err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	token.Header["jku"] = fmt.Sprintf("%s/.well-known/jwks.json", formatHost(appConfig.PublicHost))

	tokenString, err := token.SignedString(signingKey)
	if err != nil {
		appLogger.Error("Failed to sign token for client '%s': %v", clientID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// 6. Set cookie only for web clients
	if clientType == "web" {
		cookieDomain := strings.Split(strings.Replace(appConfig.PublicHost, "https://", "", 1), "/")[0]
		if strings.HasPrefix(cookieDomain, "localhost") {
			cookieDomain = "localhost"
		} else {
			parts := strings.Split(cookieDomain, ".")
			if len(parts) > 2 {
				cookieDomain = "." + parts[len(parts)-2] + "." + parts[len(parts)-1]
			}
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "anon_token",
			Value:    tokenString,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
			Domain:   cookieDomain,
		})
	}

	// 7. Send the JSON response
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
