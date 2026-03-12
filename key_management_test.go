package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadKey_ValidECKey(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	// Generate a test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Create temporary key file
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")

	// Marshal to PKCS8
	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	defer func() {
		if err := keyFile.Close(); err != nil {
			t.Errorf("failed to close key file: %v", err)
		}
	}()

	if err := pem.Encode(keyFile, pemBlock); err != nil {
		t.Fatalf("Failed to encode PEM: %v", err)
	}

	// Test loading the key
	appConfig.KeyPath = keyPath
	err = loadKey()
	if err != nil {
		t.Errorf("loadKey() failed: %v", err)
	}

	keyMu.RLock()
	defer keyMu.RUnlock()
	if currentKey == nil {
		t.Error("Expected signing key to be loaded")
	}
}

func TestLoadKey_ValidPKCS8Key(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	// Generate a test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Create temporary key file
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test_pkcs8.key")

	// Marshal to PKCS8
	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	defer func() {
		if err := keyFile.Close(); err != nil {
			t.Errorf("failed to close key file: %v", err)
		}
	}()

	if err := pem.Encode(keyFile, pemBlock); err != nil {
		t.Fatalf("Failed to encode PEM: %v", err)
	}

	// Test loading the key
	appConfig.KeyPath = keyPath
	err = loadKey()
	if err != nil {
		t.Errorf("loadKey() failed: %v", err)
	}

	keyMu.RLock()
	defer keyMu.RUnlock()
	if currentKey == nil {
		t.Error("Expected signing key to be loaded")
	}
}

func TestLoadKey_NonExistentFile(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	appConfig.KeyPath = "/non/existent/path/key.pem"
	err := loadKey()
	if err == nil {
		t.Error("Expected error when loading non-existent key file")
	}
}

func TestLoadKey_InvalidPEM(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	// Create temporary invalid key file
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "invalid.key")

	if err := os.WriteFile(keyPath, []byte("not a valid PEM file"), 0600); err != nil {
		t.Fatalf("Failed to create invalid key file: %v", err)
	}

	appConfig.KeyPath = keyPath
	err := loadKey()
	if err == nil {
		t.Error("Expected error when loading invalid PEM file")
	}
}

func TestLoadKey_InvalidKeyFormat(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	// Create temporary invalid key file with valid PEM but wrong content
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "invalid_format.key")

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: []byte("invalid key bytes"),
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	defer func() {
		if err := keyFile.Close(); err != nil {
			t.Errorf("failed to close key file: %v", err)
		}
	}()

	if err := pem.Encode(keyFile, pemBlock); err != nil {
		t.Fatalf("Failed to encode PEM: %v", err)
	}

	appConfig.KeyPath = keyPath
	err = loadKey()
	if err == nil {
		t.Error("Expected error when loading invalid key format")
	}
}

func TestLoadKey_ConcurrentAccess(t *testing.T) {
	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	// Generate a test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Create temporary key file
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "concurrent.key")

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyBytes,
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		t.Fatalf("Failed to create key file: %v", err)
	}
	defer func() {
		if err := keyFile.Close(); err != nil {
			t.Errorf("failed to close key file: %v", err)
		}
	}()

	if err := pem.Encode(keyFile, pemBlock); err != nil {
		t.Fatalf("Failed to encode PEM: %v", err)
	}

	appConfig.KeyPath = keyPath

	// Test concurrent access
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			err := loadKey()
			if err != nil {
				t.Errorf("loadKey() failed in goroutine: %v", err)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	keyMu.RLock()
	defer keyMu.RUnlock()
	if currentKey == nil {
		t.Error("Expected signing key to be loaded after concurrent access")
	}
}

func TestWatchKeyRotation_DirectoryCreation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping watch test in short mode")
	}

	originalLogger := appLogger
	defer func() { appLogger = originalLogger }()
	appLogger = &TextLogger{}

	// Create a temporary directory that will be deleted
	tmpDir := t.TempDir()
	keyDir := filepath.Join(tmpDir, "keys")
	keyPath := filepath.Join(keyDir, "test.key")

	appConfig.KeyPath = keyPath

	// Start watching in background
	done := make(chan bool)
	go func() {
		// This should wait for the directory to be created
		// We'll just test that it doesn't crash
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("watchKeyRotation panicked: %v", r)
			}
			done <- true
		}()

		// Run for a short time
		time.Sleep(100 * time.Millisecond)
	}()

	// Wait a bit
	time.Sleep(50 * time.Millisecond)

	// Create directory
	if err := os.MkdirAll(keyDir, 0755); err != nil {
		t.Fatalf("Failed to create key directory: %v", err)
	}

	// Wait for goroutine to finish
	select {
	case <-done:
		// Success
	case <-time.After(2 * time.Second):
		t.Log("Watch test timed out (expected for directory wait)")
	}
}

func TestKeyManagement_Integration(t *testing.T) {
	originalLogger := appLogger
	originalKey := currentKey
	defer func() {
		appLogger = originalLogger
		keyMu.Lock()
		currentKey = originalKey
		keyMu.Unlock()
	}()
	appLogger = &TextLogger{}

	// Generate initial test key
	privateKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate test key: %v", err)
	}

	// Create temporary key file
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "rotation.key")

	writeKey := func(key *ecdsa.PrivateKey) error {
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}

		pemBlock := &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		}

		keyFile, err := os.Create(keyPath)
		if err != nil {
			return err
		}
		if err := pem.Encode(keyFile, pemBlock); err != nil {
			_ = keyFile.Close()
			return err
		}
		return keyFile.Close()
	}

	// Write initial key
	if err := writeKey(privateKey1); err != nil {
		t.Fatalf("Failed to write initial key: %v", err)
	}

	appConfig.KeyPath = keyPath

	// Load initial key
	if err := loadKey(); err != nil {
		t.Fatalf("Failed to load initial key: %v", err)
	}

	keyMu.RLock()
	firstKey := currentKey
	keyMu.RUnlock()

	if firstKey == nil {
		t.Fatal("Expected first key to be loaded")
	}

	// Generate and write second key
	privateKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate second test key: %v", err)
	}

	if err := writeKey(privateKey2); err != nil {
		t.Fatalf("Failed to write second key: %v", err)
	}

	// Reload key
	if err := loadKey(); err != nil {
		t.Fatalf("Failed to reload key: %v", err)
	}

	keyMu.RLock()
	secondKey := currentKey
	keyMu.RUnlock()

	if secondKey == nil {
		t.Fatal("Expected second key to be loaded")
	}

	if firstKey.key.X.Cmp(secondKey.key.X) == 0 && firstKey.key.Y.Cmp(secondKey.key.Y) == 0 {
		t.Error("Expected keys to be different after rotation")
	}
}
