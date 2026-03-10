# Releasing Ghost-IDP

## Version Numbers

Version numbers are managed via **Git Tags**. We follow [Semantic Versioning](https://semver.org/):

- **MAJOR.MINOR.PATCH** (e.g., `v1.2.3`)
  - **MAJOR**: Breaking changes
  - **MINOR**: New features (backwards compatible)
  - **PATCH**: Bug fixes

## Creating a Release

### 1. Commit and push your code
```bash
git add .
git commit -m "feat: new feature description"
git push origin main
```

### 2. Create and push a tag
```bash
# Create tag locally (with message)
git tag -a v1.0.0 -m "Release v1.0.0 - Initial release"

# Push tag to GitHub
git push origin v1.0.0
```

### 3. Automated Build
The GitHub Actions workflow will automatically trigger and:
- Build the Docker image for `linux/amd64` and `linux/arm64`
- Push the image to `ghcr.io/flosk8/ghost-idp:v1.0.0`
- Create additional tags: `v1.0`, `v1`, `latest`
- Create a GitHub Release with release notes

## Using Docker Images

After the release, the image is available at:

```bash
# Specific version
docker pull ghcr.io/flosk8/ghost-idp:1.0.0

# Latest version
docker pull ghcr.io/flosk8/ghost-idp:latest

# Major version (receives all patch updates)
docker pull ghcr.io/flosk8/ghost-idp:1
```

## Testing the Image Locally

```bash
docker run -p 8080:8080 \
  -v $(pwd)/tls.key:/app/tls.key \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -e JWT_KEY_PATH=/app/tls.key \
  ghcr.io/flosk8/ghost-idp:1.0.0
```

## Embedding Version in Code

Optionally, you can embed the version in the binary:

```bash
# Build with ldflags
go build -ldflags="-X main.Version=$(git describe --tags --always)"
```

