# Testing Guide

## Running Tests

### Run all tests
```bash
go test -v ./...
# or
make test
```

### Run tests with coverage
```bash
make test-coverage
```
This generates `coverage.html` which you can open in a browser.

### Run short tests (skip long-running tests)
```bash
make test-short
```

### Run specific test
```bash
go test -v -run TestParseDuration
go test -v -run TestTokenHandler_SuccessfulMobileToken
```

### Run tests with race detector
```bash
go test -v -race ./...
```

## Test Structure

### `config_test.go`
Tests for configuration management:
- ✅ `parseDuration` - parsing time durations (2h, 30d)
- ✅ `getEnv` - environment variable retrieval
- ✅ `LoadConfig` - configuration loading from YAML and env vars
- ✅ `initClientLookup` - client lookup map initialization
- ✅ Client and TokenProfile struct validation

**Coverage:** Configuration loading, TTL parsing, environment overrides, client mapping

### `handlers_test.go`
Tests for HTTP handlers:
- ✅ `formatHost` - URL formatting
- ✅ `jwksHandler` - JWKS endpoint with/without key loaded
- ✅ `tokenHandler` - Token endpoint with various scenarios:
  - Missing client_id
  - Missing grant_type
  - Invalid grant_type
  - Invalid client_id
  - Mobile client without device_id
  - Web client without Origin header
  - Web client with invalid Origin
  - Web client with wildcard origin
  - Successful mobile token generation
  - JWT token validation

**Coverage:** Token generation, validation, JWT claims, origin checking, client authentication

### `key_management_test.go`
Tests for key loading and rotation:
- ✅ `loadKey` - Loading ECDSA keys in different formats:
  - Valid EC private key
  - Valid PKCS8 key
  - Non-existent file
  - Invalid PEM format
  - Invalid key format
  - Concurrent access (thread-safety)
- ✅ `watchKeyRotation` - Directory creation handling
- ✅ Integration test for key rotation

**Coverage:** Key loading, PEM parsing, PKCS8 support, concurrent access, key rotation

### `logger_test.go`
Tests for logging infrastructure:
- ✅ `TextLogger` - Text-based logging
  - Info level
  - Warn level
  - Error level
- ✅ `JSONLogger` - JSON-based logging
  - Valid JSON output
  - No panics
- ✅ Logger interface implementation

**Coverage:** Logging functionality, JSON formatting, interface compliance

## Test Coverage Summary

As of last run:
- **Total Tests:** 31
- **Status:** ✅ All passing
- **Race Conditions:** None detected
- **Coverage Areas:**
  - Configuration: ✅ Complete
  - Handlers: ✅ Complete
  - Key Management: ✅ Complete
  - Logging: ✅ Complete

## Coverage Report

Generate and view coverage:
```bash
make test-coverage
# Opens coverage.html in browser
```

## Writing New Tests

### Test File Naming
- File: `<source_file>_test.go`
- Example: `handlers.go` → `handlers_test.go`

### Test Function Naming
- Format: `Test<FunctionName>_<Scenario>`
- Example: `TestTokenHandler_MissingClientID`

### Table-Driven Tests
```go
tests := []struct {
    name     string
    input    string
    expected string
    wantErr  bool
}{
    {
        name:     "valid input",
        input:    "2h",
        expected: "2 hours",
        wantErr:  false,
    },
}

for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        // test logic
    })
}
```

### Using Test Fixtures
```go
// Create temporary files
tmpDir := t.TempDir()
testFile := filepath.Join(tmpDir, "test.key")
```

### Mocking Logger
```go
originalLogger := appLogger
defer func() { appLogger = originalLogger }()
appLogger = &TextLogger{}
```

## Continuous Integration

Tests run automatically in GitHub Actions on every push/PR. See `.github/workflows/ci.yml`.

## Performance Testing

Run benchmarks:
```bash
go test -bench=. -benchmem ./...
```

## Tips

- Use `-v` for verbose output
- Use `-race` to detect race conditions
- Use `-count=1` to disable test caching
- Use `-short` to skip long-running tests
- Use `-run` to run specific tests
- Use `t.Parallel()` for parallel tests (not implemented yet)

## Known Limitations

- File watcher tests are skipped in short mode
- Some tests require the `tls.key` file to exist
- JWT token tests use actual crypto operations (not mocked)

