package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

var (
	keyMu      sync.RWMutex
	signingKey *ecdsa.PrivateKey
)

func loadKey() error {
	keyBytes, err := os.ReadFile(appConfig.KeyPath)
	if err != nil {
		return err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return fmt.Errorf("no valid PEM block found")
	}

	// First try PKCS#8 (standard for Cert-Manager), then EC Private Key
	var newKey *ecdsa.PrivateKey
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		newKey = k.(*ecdsa.PrivateKey)
	} else if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		newKey = k
	} else {
		return fmt.Errorf("could not parse ECDSA key: %v", err)
	}

	keyMu.Lock()
	signingKey = newKey
	keyMu.Unlock()

	appLogger.Info("Key successfully loaded/updated.")
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

	// We watch the directory (important for K8s symlinks)
	dir := filepath.Dir(appConfig.KeyPath)
	// Ensure the directory exists before watching it
	for {
		if _, err := os.Stat(dir); err == nil {
			break
		}
		appLogger.Info("Waiting for key directory to exist: %s", dir)
		time.Sleep(5 * time.Second)
	}

	err = watcher.Add(dir)
	if err != nil {
		appLogger.Error("Error adding watcher: %v", err)
	}

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// K8s uses symlinks. If ..data is written, we reload.
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
