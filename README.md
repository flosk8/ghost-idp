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
| `device_id`       | **Mobile Only** | A unique identifier for the mobile device instance.                         |

### Example Request

```bash
curl -X POST http://localhost:8080/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=client_credentials&client_id=your-client-name"
```

The IDP validates the `client_id` and its associated configuration:
-   **Web Clients**:
    -   Validates the `Origin` header against `allowedOrigins`.
    -   Receives a `Set-Cookie` header with the JWT for easy browser integration.
-   **Mobile Clients**:
    -   Must provide a `device_id`.
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
-   **`GET /.well-known/jwks.json`**: Returns the JSON Web Key Set (JWKS).

## Outlook

### App Attestation
For enhanced mobile client security, App Attestation can be implemented. This would involve the mobile client sending an attestation payload to the `/token` endpoint, which the IDP would then verify with Apple or Google before issuing a token.
- **Android**: [Play Integrity API](https://developer.android.com/google/play/integrity/standard)
- **Apple**: [App Attest](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
