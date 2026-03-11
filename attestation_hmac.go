package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	timestampHeader = "X-Timestamp"
	signatureHeader = "X-Signature"
)

// HMACAttestationProvider validates requests using HMAC-SHA256(deviceID+timestamp, clientSecret).
type HMACAttestationProvider struct{}

func (HMACAttestationProvider) Verify(_ context.Context, deviceID string, r *http.Request, clientID, clientType string) (*AttestationResult, error) {
	if clientType != "mobile" {
		return &AttestationResult{Level: "hmac-not-required"}, nil
	}

	timestamp := strings.TrimSpace(r.Header.Get(timestampHeader))
	signature := strings.TrimSpace(r.Header.Get(signatureHeader))
	if timestamp == "" {
		return nil, fmt.Errorf("missing %s header", timestampHeader)
	}
	if signature == "" {
		return nil, fmt.Errorf("missing %s header", signatureHeader)
	}

	parsedTimestamp, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid %s header: must be unix seconds", timestampHeader)
	}

	maxAgeSeconds := appConfig.Attestation.MaxAgeSeconds
	if maxAgeSeconds <= 0 {
		maxAgeSeconds = 60
	}

	ts := time.Unix(parsedTimestamp, 0)
	now := time.Now()
	age := now.Sub(ts)
	if age < 0 {
		return nil, fmt.Errorf("%s is in the future", timestampHeader)
	}
	if age > time.Duration(maxAgeSeconds)*time.Second {
		return nil, fmt.Errorf("%s too old", timestampHeader)
	}

	secret := strings.TrimSpace(hmacSecretLookupMap[clientID])
	if secret == "" {
		return nil, fmt.Errorf("missing hmacSecret for mobile client '%s'", clientID)
	}

	expectedMAC := hmac.New(sha256.New, []byte(secret))
	expectedMAC.Write([]byte(deviceID + timestamp))
	expectedSignature := hex.EncodeToString(expectedMAC.Sum(nil))

	if !hmac.Equal([]byte(strings.ToLower(signature)), []byte(strings.ToLower(expectedSignature))) {
		return nil, fmt.Errorf("signature mismatch")
	}

	return &AttestationResult{Level: "hmac"}, nil
}
