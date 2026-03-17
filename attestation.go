package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var (
	ErrAttestationMissing = errors.New("attestation token is required")
	ErrAttestationInvalid = errors.New("attestation token is invalid")
)

// AttestationResult contains optional metadata returned by a provider.
type AttestationResult struct {
	Level string
}

// AttestationProvider validates attestations for incoming token requests.
type AttestationProvider interface {
	Verify(ctx context.Context, token string, r *http.Request, clientID, clientType string) (*AttestationResult, error)
}

type NoopAttestationProvider struct{}

func (NoopAttestationProvider) Verify(_ context.Context, token string, _ *http.Request, _, _ string) (*AttestationResult, error) {
	if strings.TrimSpace(token) == "" {
		return nil, ErrAttestationMissing
	}
	return &AttestationResult{Level: "stub"}, nil
}

var attestationProvider AttestationProvider = NoopAttestationProvider{}

func initAttestationProvider() {
	switch strings.ToLower(strings.TrimSpace(appConfig.Attestation.Provider)) {
	case "", "noop", "stub":
		attestationProvider = NoopAttestationProvider{}
	default:
		appLogger.Warn("Unknown attestation provider '%s'. Falling back to noop provider.", appConfig.Attestation.Provider)
		attestationProvider = NoopAttestationProvider{}
	}
}

func requiresAttestation(clientType string) bool {
	if !appConfig.Attestation.Enabled {
		return false
	}

	if len(appConfig.Attestation.RequiredFor) == 0 {
		return true
	}

	for _, t := range appConfig.Attestation.RequiredFor {
		if strings.EqualFold(strings.TrimSpace(t), clientType) {
			return true
		}
	}
	return false
}

func extractAttestationToken(r *http.Request) string {
	return strings.TrimSpace(r.FormValue("device_id"))
}

func verifyRequestAttestation(r *http.Request, clientID, clientType string) (*AttestationResult, error) {
	if !requiresAttestation(clientType) {
		return nil, nil
	}

	token := extractAttestationToken(r)
	if token == "" {
		return nil, ErrAttestationMissing
	}

	result, err := attestationProvider.Verify(r.Context(), token, r, clientID, clientType)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestationInvalid, err)
	}
	return result, nil
}
