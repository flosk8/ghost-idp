# Releasing Ghost-IDP

## Versionsnummern

Die Versionsnummer wird über **Git Tags** verwaltet. Wir folgen [Semantic Versioning](https://semver.org/):

- **MAJOR.MINOR.PATCH** (z.B. `v1.2.3`)
  - **MAJOR**: Breaking Changes
  - **MINOR**: Neue Features (rückwärtskompatibel)
  - **PATCH**: Bugfixes

## Release erstellen

### 1. Code committen und pushen
```bash
git add .
git commit -m "feat: neue Feature-Beschreibung"
git push origin main
```

### 2. Tag erstellen und pushen
# Tag lokal erstellen (mit Nachricht)
```bash
git tag -a v1.0.0 -m "Release v1.0.0 - Initial release"

# Tag zu GitHub pushen
git push origin v1.0.0
```

### 3. Automatischer Build
Der GitHub Actions Workflow wird automatisch getriggert und:
- Baut das Docker Image für `linux/amd64` und `linux/arm64`
- Pusht das Image zu `ghcr.io/OWNER/ghost-idp:v1.0.0`
- Erstellt zusätzliche Tags: `v1.0`, `v1`, `latest`
- Erstellt ein GitHub Release mit Release Notes

## Docker Images verwenden

Nach dem Release ist das Image verfügbar unter:

```bash
# Spezifische Version
docker pull ghcr.io/ndrde/ghost-idp:v1.0.0

# Neueste Version
docker pull ghcr.io/ndrde/ghost-idp:latest

# Major Version (erhält alle Patch-Updates)
docker pull ghcr.io/ndrde/ghost-idp:v1
```

## Image lokal testen

```bash
docker run -p 8080:8080 \
  -v $(pwd)/tls.key:/app/tls.key \
  -v $(pwd)/config.yaml:/app/config.yaml \
  -e JWT_KEY_PATH=/app/tls.key \
  ghcr.io/ndrde/ghost-idp:v1.0.0
```

## Versionsnummer im Code anzeigen

Optional kann man die Version auch im Code verfügbar machen:

```bash
# Bei Build mit ldflags
go build -ldflags="-X main.Version=$(git describe --tags --always)"
```

