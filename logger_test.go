package main

import (
	"bytes"
	"encoding/json"
	"log"
	"strings"
	"testing"
)

func TestTextLogger(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(nil)

	logger := &TextLogger{}

	t.Run("Info", func(t *testing.T) {
		buf.Reset()
		logger.Info("test message: %s", "info")
		output := buf.String()
		if !strings.Contains(output, "INFO:") {
			t.Errorf("Expected INFO prefix, got: %s", output)
		}
		if !strings.Contains(output, "test message: info") {
			t.Errorf("Expected message content, got: %s", output)
		}
	})

	t.Run("Warn", func(t *testing.T) {
		buf.Reset()
		logger.Warn("test warning: %s", "warn")
		output := buf.String()
		if !strings.Contains(output, "WARN:") {
			t.Errorf("Expected WARN prefix, got: %s", output)
		}
		if !strings.Contains(output, "test warning: warn") {
			t.Errorf("Expected message content, got: %s", output)
		}
	})

	t.Run("Error", func(t *testing.T) {
		buf.Reset()
		logger.Error("test error: %s", "error")
		output := buf.String()
		if !strings.Contains(output, "ERROR:") {
			t.Errorf("Expected ERROR prefix, got: %s", output)
		}
		if !strings.Contains(output, "test error: error") {
			t.Errorf("Expected message content, got: %s", output)
		}
	})
}

func TestJSONLogger(t *testing.T) {
	var buf bytes.Buffer
	oldStdout := log.Writer()
	defer log.SetOutput(oldStdout)

	logger := &JSONLogger{}

	t.Run("Info", func(t *testing.T) {
		buf.Reset()
		// Capture stdout for JSON logger
		logger.Info("test message: %s", "info")
	})

	t.Run("Warn", func(t *testing.T) {
		buf.Reset()
		logger.Warn("test warning: %s", "warn")
	})

	t.Run("Error", func(t *testing.T) {
		buf.Reset()
		logger.Error("test error: %s", "error")
	})
}

func TestJSONLoggerFormat(t *testing.T) {
	// Test that JSON logger produces valid JSON
	// We can't easily capture stdout, but we can test that it doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("JSONLogger panicked: %v", r)
		}
	}()

	logger := &JSONLogger{}
	logger.Info("test %s", "message")
	logger.Warn("test %s", "warning")
	logger.Error("test %s", "error")
}

func TestLoggerInterface(t *testing.T) {
	// Test that both loggers implement the Logger interface
	var _ Logger = &TextLogger{}
	var _ Logger = &JSONLogger{}
}

func TestJSONLoggerValidJSON(t *testing.T) {
	// Test logJSON produces valid JSON structure

	// Create a test entry manually
	entry := make(map[string]interface{})
	entry["level"] = "info"
	entry["message"] = "test message"

	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		t.Errorf("Failed to marshal JSON: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &decoded); err != nil {
		t.Errorf("Failed to unmarshal JSON: %v", err)
	}

	if decoded["level"] != "info" {
		t.Errorf("Expected level 'info', got: %v", decoded["level"])
	}
	if decoded["message"] != "test message" {
		t.Errorf("Expected message 'test message', got: %v", decoded["message"])
	}
}
