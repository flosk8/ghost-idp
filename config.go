package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Client represents a single client entry in the config.
type Client struct {
	Name           string   `yaml:"name"`
	Config         string   `yaml:"config,omitempty"`
	AllowedOrigins []string `yaml:"allowedOrigins,omitempty"`
}

// TokenProfile defines a set of token properties like TTL and audience.
type TokenProfile struct {
	TTL      string   `yaml:"ttl"`
	Audience []string `yaml:"audience"`
}

// TokenConfig holds the global TTL and the configuration profiles.
type TokenConfig struct {
	TTL    string                  `yaml:"ttl"`
	Config map[string]TokenProfile `yaml:"config"`
}

// Clients groups web and mobile clients.
type Clients struct {
	Web    []Client `yaml:"web"`
	Mobile []Client `yaml:"mobile"`
}

// AttestationConfig holds the configuration for attestation options.
type AttestationConfig struct {
	Enabled     bool     `yaml:"enabled"`
	RequiredFor []string `yaml:"requiredFor"`
	Provider    string   `yaml:"provider"`
}

// AppConfig holds the entire application configuration.
type AppConfig struct {
	Token       TokenConfig       `yaml:"token"`
	Clients     Clients           `yaml:"clients"`
	Attestation AttestationConfig `yaml:"attestation,omitempty"`
	KeyPath     string            `yaml:"keyPath,omitempty"`
	PublicHost  string            `yaml:"publicHost,omitempty"`
}

const (
	clientTypeWeb    = "web"
	clientTypeMobile = "mobile"
)

var (
	appConfig         AppConfig
	clientLookupMap   map[string]string
	originLookupMap   map[string][]string
	audienceLookupMap map[string][]string
	ttlLookupMap      map[string]time.Duration
)

func initClientLookup() {
	clientLookupMap = make(map[string]string)
	originLookupMap = make(map[string][]string)
	audienceLookupMap = make(map[string][]string)
	ttlLookupMap = make(map[string]time.Duration)

	globalTTL, err := parseDuration(appConfig.Token.TTL)
	if err != nil {
		appLogger.Fatal("Invalid global token TTL format: %v", err)
	}

	registerClients(appConfig.Clients.Web, clientTypeWeb, globalTTL)
	registerClients(appConfig.Clients.Mobile, clientTypeMobile, globalTTL)

	appLogger.Info("Initialized client lookup map with %d clients.", len(clientLookupMap))
}

func registerClients(clients []Client, clientType string, globalTTL time.Duration) {
	for _, client := range clients {
		clientLookupMap[client.Name] = clientType
		if clientType == clientTypeWeb {
			originLookupMap[client.Name] = client.AllowedOrigins
		}

		ttlLookupMap[client.Name] = globalTTL

		if configRef := client.Config; configRef != "" {
			if profile, found := appConfig.Token.Config[configRef]; found {
				audienceLookupMap[client.Name] = profile.Audience

				if profile.TTL != "" {
					if profileTTL, err := parseDuration(profile.TTL); err == nil {
						ttlLookupMap[client.Name] = profileTTL
					} else {
						appLogger.Warn("Invalid TTL format for profile '%s' used by client '%s'. Using global default. Error: %v", configRef, client.Name, err)
					}
				}
			} else {
				appLogger.Warn("Token config reference '%s' for client '%s' not found. Using global default TTL.", configRef, client.Name)
			}
		}
	}
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func LoadConfig(configPath string) error {
	appConfig.KeyPath = "/etc/ghost-idp/certs/tls.key"
	appConfig.PublicHost = "http://localhost:8080"
	appConfig.Token.TTL = "2h"
	appConfig.Attestation.Enabled = false
	appConfig.Attestation.RequiredFor = []string{"mobile"}
	appConfig.Attestation.Provider = "noop"

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			appLogger.Warn("config.yaml not found at %s. Using environment variables and default values.", configPath)
		} else {
			return fmt.Errorf("failed to read config file %s: %w", configPath, err)
		}
	} else {
		if err := yaml.Unmarshal(data, &appConfig); err != nil {
			return fmt.Errorf("failed to unmarshal config file %s: %w", configPath, err)
		}
		appLogger.Info("Configuration loaded from %s.", configPath)
	}

	applyEnvOverrides()
	return nil
}

func applyEnvOverrides() {
	if keyPath, ok := os.LookupEnv("JWT_KEY_PATH"); ok {
		appConfig.KeyPath = keyPath
	}
	if publicHost, ok := os.LookupEnv("PUBLIC_HOST"); ok {
		appConfig.PublicHost = publicHost
	}
	if tokenTTL, ok := os.LookupEnv("TOKEN_TTL"); ok {
		appConfig.Token.TTL = tokenTTL
		appLogger.Info("Global token TTL overridden by TOKEN_TTL environment variable: %s", tokenTTL)
	}
	if attestationEnabled, ok := os.LookupEnv("ATTESTATION_ENABLED"); ok {
		if enabled, err := strconv.ParseBool(attestationEnabled); err == nil {
			appConfig.Attestation.Enabled = enabled
		} else {
			appLogger.Warn("Invalid ATTESTATION_ENABLED value '%s'. Keeping current value: %t", attestationEnabled, appConfig.Attestation.Enabled)
		}
	}
	if requiredFor, ok := os.LookupEnv("ATTESTATION_REQUIRED_FOR"); ok {
		parts := strings.Split(requiredFor, ",")
		resolved := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				resolved = append(resolved, p)
			}
		}
		appConfig.Attestation.RequiredFor = resolved
	}
	if provider, ok := os.LookupEnv("ATTESTATION_PROVIDER"); ok && strings.TrimSpace(provider) != "" {
		appConfig.Attestation.Provider = strings.TrimSpace(provider)
	}

	for profileName, profile := range appConfig.Token.Config {
		envVarName := fmt.Sprintf("TOKEN_CONFIG_%s_TTL", strings.ToUpper(profileName))
		if profileTTL, ok := os.LookupEnv(envVarName); ok {
			// Maps return copies in Go, so we must reassign after modifying.
			mutableProfile := profile
			mutableProfile.TTL = profileTTL
			appConfig.Token.Config[profileName] = mutableProfile
			appLogger.Info("TTL for profile '%s' overridden by %s: %s", profileName, envVarName, profileTTL)
		}
	}
}

// parseDuration parses a duration string with units 'h' (hours) or 'd' (days).
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid format: %s", s)
	}

	unit := s[len(s)-1]
	valueStr := s[:len(s)-1]

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return 0, fmt.Errorf("invalid numeric value: %w", err)
	}

	switch unit {
	case 'h':
		return time.Duration(value) * time.Hour, nil
	case 'd':
		return time.Duration(value) * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("unknown time unit: %c; expected 'h' for hours or 'd' for days", unit)
	}
}
