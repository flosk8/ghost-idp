package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

// Logger Interface
type Logger interface {
	Info(format string, v ...interface{})
	Warn(format string, v ...interface{})
	Error(format string, v ...interface{})
	Fatal(format string, v ...interface{})
}

// TextLogger implementation
type TextLogger struct{}

func (l *TextLogger) Info(format string, v ...interface{}) {
	log.Printf("INFO: "+format, v...)
}

func (l *TextLogger) Warn(format string, v ...interface{}) {
	log.Printf("WARN: "+format, v...)
}

func (l *TextLogger) Error(format string, v ...interface{}) {
	log.Printf("ERROR: "+format, v...)
}

func (l *TextLogger) Fatal(format string, v ...interface{}) {
	log.Fatalf("FATAL: "+format, v...)
}

// JSONLogger implementation
type JSONLogger struct{}

func (l *JSONLogger) logJSON(level, format string, v ...interface{}) {
	entry := make(map[string]interface{})
	entry["timestamp"] = time.Now().Format(time.RFC3339)
	entry["level"] = level
	entry["message"] = fmt.Sprintf(format, v...)

	jsonBytes, err := json.Marshal(entry)
	if err != nil {
		// Fallback to text logging if JSON marshaling fails
		log.Printf("ERROR: Failed to marshal JSON log entry: %v. Original message: %s", err, fmt.Sprintf(format, v...))
		return
	}
	fmt.Println(string(jsonBytes))
}

func (l *JSONLogger) Info(format string, v ...interface{}) {
	l.logJSON("info", format, v...)
}

func (l *JSONLogger) Warn(format string, v ...interface{}) {
	l.logJSON("warn", format, v...)
}

func (l *JSONLogger) Error(format string, v ...interface{}) {
	l.logJSON("error", format, v...)
}

func (l *JSONLogger) Fatal(format string, v ...interface{}) {
	l.logJSON("fatal", format, v...)
	os.Exit(1) // JSONLogger needs to explicitly exit on Fatal
}
