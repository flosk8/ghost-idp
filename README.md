# Ghost-IDP

A lightweight, standalone Identity Provider for generating anonymous JWTs using ECDSA keys.

## Features

-   **ECDSA Key Support**: Signs tokens using ES256.
-   **Key Rotation**: Automatically detects and reloads keys when the key file changes.
-   **JWKS Endpoint**: Provides a `/.well-known/jwks.json` endpoint for public key discovery.
-   **Structured Logging**: Supports both plain text and JSON-formatted logs.
-   **Advanced Configuration**:
    -   **Client Whitelisting**: Restricts token issuance to a predefined list of clients.
    -   **Configuration Profiles**: Define token profiles (`dev`, `prod`) with specific TTLs and audiences.
    -   **Origin Validation**: Validates the `Origin` header for web clients.
-   **Rich JWT Claims**: Includes `client_id`, `client_ip`, `device_id` (for mobile), and a configurable `aud` (audience) claim.

## How it Works

To receive a token, a client must send a `POST` request to the `/token` endpoint with an `x-www-form-urlencoded` body.

### Request Parameters

| Parameter         | Required | Description                                                                 |
|-------------------|----------|-----------------------------------------------------------------------------|
| `grant_type`      | Yes      | Must be set to `client_credentials`.                                        |
| `client_id`       | Yes      | The unique identifier of the client as defined in `config.yaml`.            |
| `device_id`       | **Mobile Only** | Device identifier — sent as form field or via `X-Device-Id` header (one of the two is required). Becomes the `device_id` claim in the JWT. |

### Example Request

```bash
# Mobile client — device_id as form field
curl -X POST http://localhost:8080/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=client_credentials&client_id=your-mobile-client&device_id=my-device-id"

# Mobile client — device_id as header
curl -X POST http://localhost:8080/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -H "X-Device-Id: my-device-id" \
     -d "grant_type=client_credentials&client_id=your-mobile-client"
```

The IDP validates the `client_id` and its associated configuration:
-   **Web Clients**:
    -   Validates the `Origin` header against `allowedOrigins`.
    -   Receives a `Set-Cookie` header with the JWT for easy browser integration.
-   **Mobile Clients**:
    -   Must provide a device identifier via the `device_id` form field **or** the `X-Device-Id` header (form field takes precedence if both are set).
    -   The value is included as the `device_id` claim in the JWT.
    -   Do not receive a cookie and are expected to use the `access_token` from the JSON response body.

## Configuration

The application is configured via `config.yaml` and can be extensively overridden with environment variables.

### `config.yaml`

This file defines token profiles and allowed clients.

```yaml
# config.yaml

# Public-facing host for the IDP
publicHost: http://localhost:8080
# Path to the ECDSA private key
keyPath: ./tls.key

attestation:
  enabled: false
  requiredFor:
    - mobile
  headerName: X-Device-Id
  formField: device_id
  provider: noop

# Token configuration section
token:
  # Global default TTL if not specified in a profile
  ttl: 2h
  # Reusable configuration profiles for tokens
  config:
    dev:
      ttl: 2h
      audience:
        - kompass-dev
        - kompass-qa
    prod:
      ttl: 4h
      audience:
        - kompass-prod

# Client definitions
clients:
  web:
    - name: "atlas-dev"
      config: "dev"       # References the 'dev' profile from token.config
      allowedOrigins:
        - "*"             # Allow all origins (use with caution)
    - name: "brde-dev"
      config: "dev"
      allowedOrigins:
        - "https://br.de"
        - "https://br.dev.de"
  mobile:
    - name: "br24-dev"
      config: "dev"
```

### Configuration Precedence

The final configuration is determined in the following order (later steps override earlier ones):

1.  **Hardcoded Defaults**: The application has built-in defaults (e.g., `token.ttl: 2h`).
2.  **`config.yaml`**: Values from this file override the hardcoded defaults.
3.  **Environment Variables**: Specific environment variables can override any of the above values. This is especially useful for managing token TTLs.

#### Token TTL Precedence

The Time-To-Live (TTL) for a token is resolved with the following priority:

1.  **Profile-Specific Environment Variable**: `TOKEN_CONFIG_<PROFILE>_TTL` (e.g., `TOKEN_CONFIG_PROD_TTL=1h`) will override everything for clients using that profile.
2.  **Profile `ttl` in `config.yaml`**: The `ttl` defined inside a `token.config` profile.
3.  **Global `TOKEN_TTL` Environment Variable**: Overrides the global default TTL.
4.  **Global `ttl` in `config.yaml`**: The top-level `token.ttl` value.
5.  **Hardcoded Default**: `2h`.

### Environment Variables

| Variable                      | Description                                                                 | Default                               |
|-------------------------------|-----------------------------------------------------------------------------|---------------------------------------|
| `JWT_KEY_PATH`                | Path to the ECDSA private key file.                                         | `/etc/ghost-idp/certs/tls.key`        |
| `PUBLIC_HOST`                 | Public-facing host for the JWKS endpoint.                                   | `http://localhost:8080`               |
| `LOG_FORMAT`                  | The format for application logs (`text` or `json`).                         | `text`                                |
| `TOKEN_TTL`                   | Overrides the **global** default token TTL (e.g., `30d`, `12h`).             | `token.ttl` from `config.yaml`        |
| `TOKEN_CONFIG_<PROFILE>_TTL`  | Overrides the TTL for a **specific profile** (e.g., `TOKEN_CONFIG_PROD_TTL=1h`). | `ttl` from the profile in `config.yaml` |
| `ATTESTATION_ENABLED`         | Enables request-time attestation validation.                                 | `false`                               |
| `ATTESTATION_REQUIRED_FOR`    | Comma-separated client types requiring attestation (e.g. `mobile,web`).     | `mobile`                              |
| `ATTESTATION_HEADER`          | Header used to read attestation data.                                        | `X-Device-Id`                         |
| `ATTESTATION_FORM_FIELD`      | Form field used to read attestation data.                                    | `device_id`                           |
| `ATTESTATION_PROVIDER`        | Attestation provider id (`noop` scaffold by default).                        | `noop`                                |


## Getting Started

### Running Locally

1.  **Prerequisites**: Go 1.24 or higher.
2.  **Generate a Key**:
    ```bash
    openssl ecparam -name prime256v1 -genkey -noout -out tls.key
    ```
3.  **Create `config.yaml`**: Create the configuration file as shown above.
4.  **Run the Application**:
    ```bash
    go run .
    ```

### Running with Docker

1.  **Build the Docker Image**:
    ```bash
    docker build -t ghost-idp:local .
    ```
2.  **Run the Docker Container**:
    ```bash
    docker run -p 8080:8080 \
      -v $(pwd)/tls.key:/app/tls.key \
      -v $(pwd)/config.yaml:/app/config.yaml \
      -e JWT_KEY_PATH=/app/tls.key \
      -e TOKEN_CONFIG_PROD_TTL=1h \
      --name ghost-test \
      ghost-idp:local
    ```

## Endpoints

-   **`POST /token`**: Generates and returns a new JWT for a validated client.
-   **`GET /.well-known/jwks.json`**: Returns the JSON Web Key Set (JWKS). CORS enabled for public access (e.g. jwt.io).
-   **`GET /.well-known/openid-configuration`**: OIDC Discovery endpoint – allows tools like jwt.io to automatically find the public key.
-   **`GET /healthz`**: Liveness probe – always returns `200 ok`.
-   **`GET /readyz`**: Readiness probe – returns `200 ready` when the signing key is loaded, `503` otherwise.

## Testing

The project includes comprehensive unit tests covering:

### Test Coverage
- **45+ tests** covering:
  - Configuration loading and precedence
  - Token generation and validation (web and mobile clients)
  - JWKS endpoint and OIDC Discovery
  - Health (`/healthz`) and readiness (`/readyz`) probes
  - Request logging with probe filtering
  - Origin validation for web clients
  - Device ID handling for mobile clients
  - CORS header validation
  - Key management and rotation
  - Logger (text and JSON format)
  - Concurrent access to signing keys

### Run Tests
```bash
# Run all tests
make test

# Run tests with coverage report
make test-coverage

# Run specific test
go test -v -run TestTokenHandler_SuccessfulMobileToken
```

### Test Details
- **Race detector**: Enabled via `-race` flag for concurrent operation safety
- **Request logger tests**: Verify that health probes are properly filtered from logs
- **CORS tests**: Confirm that jwt.io can fetch public keys automatically
- **Key management tests**: Cover ECDSA key loading, PKCS#8 format, and concurrent access
- **CI/CD**: Tests run automatically on every push via GitHub Actions

See [TESTING.md](TESTING.md) for detailed testing documentation.

## App Attestation

Ghost-IDP includes an attestation scaffold that can verify that token requests originate from genuine, unmodified app installs before issuing a JWT.

### How It Works

1. The mobile client sends a device identifier / attestation payload via the `device_id` form field or the `X-Device-Id` header.
2. Ghost-IDP extracts the value and passes it to the configured `AttestationProvider`.
3. If the provider accepts the token, the JWT will contain extra claims:
   - `attested: true`
   - `attestation_level: "<value from provider>"`
4. If the provider rejects it, the request is denied with `400` (missing) or `403` (invalid).

### Enabling Attestation

Set `attestation.enabled: true` in `config.yaml` or via environment variable:

```yaml
attestation:
  enabled: true
  requiredFor:
    - mobile        # enforce only for mobile clients; add "web" to also enforce for web clients
  headerName: X-Device-Id
  formField: device_id
  provider: noop    # replace with your provider id once implemented
```

Or via environment variables:

```bash
ATTESTATION_ENABLED=true
ATTESTATION_REQUIRED_FOR=mobile
ATTESTATION_PROVIDER=play-integrity   # example
```

### Adding a Custom Provider

All attestation logic lives in `attestation.go`. To add a real provider:

1. **Implement the interface** — create a new file, e.g. `attestation_play_integrity.go`:

```go
package main

import (
    "context"
    "fmt"
    "net/http"
)

type PlayIntegrityProvider struct {
    // e.g. GoogleCredentials, ProjectID, etc.
}

func (p PlayIntegrityProvider) Verify(ctx context.Context, token string, r *http.Request, clientID, clientType string) (*AttestationResult, error) {
    // Call the Play Integrity API here
    // Return AttestationResult on success, error on failure
    if token == "" {
        return nil, fmt.Errorf("empty token")
    }
    // ... real verification logic ...
    return &AttestationResult{Level: "strong"}, nil
}
```

2. **Register the provider** — add a case in `initAttestationProvider()` in `attestation.go`:

```go
case "play-integrity":
    attestationProvider = PlayIntegrityProvider{ /* inject config */ }
case "app-attest":
    attestationProvider = AppleAppAttestProvider{ /* inject config */ }
```

3. **Set the provider** in `config.yaml`:

```yaml
attestation:
  enabled: true
  provider: play-integrity
```

### Platform Documentation

- **Android**: [Play Integrity API](https://developer.android.com/google/play/integrity/standard)
- **Apple**: [App Attest](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)

## Outlook

