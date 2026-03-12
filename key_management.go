package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

type keyEntry struct {
	key *ecdsa.PrivateKey
	kid string
}

var (
	keyMu      sync.RWMutex
	currentKey *keyEntry
)

// computeKID derives a stable key ID from the public key using the RFC 7638 JWK Thumbprint.
func computeKID(pub *ecdsa.PublicKey) string {
	x := base64.RawURLEncoding.EncodeToString(pub.X.Bytes())
	y := base64.RawURLEncoding.EncodeToString(pub.Y.Bytes())
	// Fields must be in lexicographic order per RFC 7638.
	thumbprintJSON, err := json.Marshal(map[string]string{
		"crv": "P-256",
		"kty": "EC",
		"x":   x,
		"y":   y,
	})
	if err != nil {
		panic(fmt.Sprintf("computeKID: unexpected json.Marshal error: %v", err))
	}
	h := sha256.Sum256(thumbprintJSON)
	return base64.RawURLEncoding.EncodeToString(h[:8])
}

func parseECKeyFromFile(path string) (*ecdsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("no valid PEM block found in %s", path)
	}
	// Try PKCS#8 first (standard for cert-manager), then fall back to legacy EC private key format.
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return k.(*ecdsa.PrivateKey), nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, fmt.Errorf("could not parse ECDSA key from %s", path)
}

func loadKey() error {
	newKey, err := parseECKeyFromFile(appConfig.KeyPath)
	if err != nil {
		return err
	}

	entry := &keyEntry{
		key: newKey,
		kid: computeKID(newKey.Public().(*ecdsa.PublicKey)),
	}

	keyMu.Lock()
	currentKey = entry
	keyMu.Unlock()

	appLogger.Info("Key successfully loaded/updated (kid: %s).", entry.kid)
	return nil
}

func watchKeyRotation() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		appLogger.Fatal("Failed to create file system watcher: %v", err)
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			appLogger.Error("Failed to close watcher: %v", err)
		}
	}()

	// Watch the directory instead of the file to handle K8s secret symlink rotations.
	dir := filepath.Dir(appConfig.KeyPath)
	for {
		if _, err := os.Stat(dir); err == nil {
			break
		}
		appLogger.Info("Waiting for key directory to exist: %s", dir)
		time.Sleep(5 * time.Second)
	}

	if err = watcher.Add(dir); err != nil {
		appLogger.Error("Error adding watcher: %v", err)
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// K8s rotates secrets by rewriting the ..data symlink, which triggers a Create event.
			if event.Has(fsnotify.Create) || event.Has(fsnotify.Write) {
				appLogger.Info("Rotation detected, reloading key...")
				if err := loadKey(); err != nil {
					appLogger.Error("Error reloading key after rotation: %v", err)
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			appLogger.Error("Watcher error: %v", err)
		}
	}
}
