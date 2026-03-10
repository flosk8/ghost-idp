package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Client represents a single client entry in the config
type Client struct {
	Name           string   `yaml:"name"`
	Config         string   `yaml:"config,omitempty"` // Reference to a token config profile
	AllowedOrigins []string `yaml:"allowedOrigins,omitempty"`
}

// TokenProfile defines a set of token properties like TTL and audience
type TokenProfile struct {
	TTL      string   `yaml:"ttl"`
	Audience []string `yaml:"audience"`
}

// TokenConfig holds the global TTL and the configuration profiles
type TokenConfig struct {
	TTL    string                  `yaml:"ttl"`
	Config map[string]TokenProfile `yaml:"config"`
}

// Clients groups web and mobile clients
type Clients struct {
	Web    []Client `yaml:"web"`
	Mobile []Client `yaml:"mobile"`
}

// AppConfig holds the entire application configuration
type AppConfig struct {
	Token      TokenConfig `yaml:"token"`
	Clients    Clients     `yaml:"clients"`
	KeyPath    string      `yaml:"keyPath,omitempty"`
	PublicHost string      `yaml:"publicHost,omitempty"`
}

// Global variables
var (
	appConfig         AppConfig
	clientLookupMap   map[string]string        // Map to store client_id -> client_type ("web" or "mobile")
	originLookupMap   map[string][]string      // Map to store client_id -> allowed_origins for web clients
	audienceLookupMap map[string][]string      // Map to store client_id -> resolved audience list
	ttlLookupMap      map[string]time.Duration // Map to store client_id -> resolved TTL
)

// initClientLookup creates a fast lookup map from the loaded client configuration.
func initClientLookup() {
	clientLookupMap = make(map[string]string)
	originLookupMap = make(map[string][]string)
	audienceLookupMap = make(map[string][]string)
	ttlLookupMap = make(map[string]time.Duration)

	// Global default TTL
	globalTTL, err := parseDuration(appConfig.Token.TTL)
	if err != nil {
		appLogger.Fatal("Invalid global token TTL format: %v", err)
	}

	// Helper function to process clients
	processClients := func(clients []Client, clientType string) {
		for _, client := range clients {
			clientLookupMap[client.Name] = clientType
			if clientType == "web" {
				originLookupMap[client.Name] = client.AllowedOrigins
			}

			// Set default TTL first
			ttlLookupMap[client.Name] = globalTTL

			// Resolve config reference
			if configRef := client.Config; configRef != "" {
				if profile, found := appConfig.Token.Config[configRef]; found {
					// Set audience
					audienceLookupMap[client.Name] = profile.Audience

					// Set TTL if specified in profile
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

	processClients(appConfig.Clients.Web, "web")
	processClients(appConfig.Clients.Mobile, "mobile")

	appLogger.Info("Initialized client lookup map with %d clients.", len(clientLookupMap))
}

// getEnv retrieves an environment variable or returns a fallback value.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

// LoadConfig reads the config.yaml file and populates appConfig.
func LoadConfig(configPath string) error {
	// 1. Set hardcoded defaults
	appConfig.KeyPath = "/etc/ghost-idp/certs/tls.key"
	appConfig.PublicHost = "http://localhost:8080"
	appConfig.Token.TTL = "2h" // Default for global TTL

	// 2. Read config.yaml and unmarshal it
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			appLogger.Warn("config.yaml not found at %s. Using environment variables and default values.", configPath)
			// Continue without error, as env vars can still be used
		} else {
			return fmt.Errorf("failed to read config file %s: %w", configPath, err)
		}
	} else {
		// Unmarshal YAML data into appConfig, overriding hardcoded defaults
		if err := yaml.Unmarshal(data, &appConfig); err != nil {
			return fmt.Errorf("failed to unmarshal config file %s: %w", configPath, err)
		}
		appLogger.Info("Configuration loaded from %s.", configPath)
	}

	// 3. Override with environment variables if they are set
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

	// 4. Override profile-specific TTLs with environment variables
	for profileName, profile := range appConfig.Token.Config {
		envVarName := fmt.Sprintf("TOKEN_CONFIG_%s_TTL", strings.ToUpper(profileName))
		if profileTTL, ok := os.LookupEnv(envVarName); ok {
			// Create a mutable copy of the profile, modify it, and update the map
			mutableProfile := profile
			mutableProfile.TTL = profileTTL
			appConfig.Token.Config[profileName] = mutableProfile
			appLogger.Info("TTL for profile '%s' overridden by %s: %s", profileName, envVarName, profileTTL)
		}
	}

	return nil
}

// parseDuration parses a string like "2h" or "30d" into a time.Duration.
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
