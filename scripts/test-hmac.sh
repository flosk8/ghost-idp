BASE_URL="http://localhost:8080"
CLIENT_ID="kompass-mobile-dev"
DEVICE_ID="my-test-device-001"
SECRET="dev-secret-change-me"

TIMESTAMP="$(date +%s)"
SIGNATURE="$(printf "%s%s" "$DEVICE_ID" "$TIMESTAMP" | openssl dgst -sha256 -hmac "$SECRET" -binary | xxd -p -c 256)"

curl -sS -X POST "${BASE_URL}/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -H "X-Device-Id: ${DEVICE_ID}" \
  -H "X-Timestamp: ${TIMESTAMP}" \
  -H "X-Signature: ${SIGNATURE}" \
  --data "grant_type=client_credentials&client_id=${CLIENT_ID}"
