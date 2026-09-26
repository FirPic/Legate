#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
elif command -v podman-compose >/dev/null 2>&1; then
    COMPOSE="podman-compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose"
else
    echo "Error: neither docker compose nor podman-compose found" >&2
    exit 1
fi

cleanup() {
    echo "==> Cleaning up E2E test stack..."
    $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Building and starting Legate E2E test stack..."
$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
$COMPOSE up -d --build

echo "==> Waiting for Traefik to request and obtain ACME certificate from Pebble via Legate..."
MAX_WAIT_SECONDS=45
START_TIME=$(date +%s)
CERT_FOUND=0

while [ $(($(date +%s) - START_TIME)) -lt $MAX_WAIT_SECONDS ]; do
    if $COMPOSE exec -T traefik test -f /letsencrypt/acme.json 2>/dev/null; then
        ACME_CONTENT=$($COMPOSE exec -T traefik cat /letsencrypt/acme.json 2>/dev/null || true)
        if echo "$ACME_CONTENT" | grep -q "app.test.firpic.fr" && echo "$ACME_CONTENT" | grep -q "certificate"; then
            CERT_FOUND=1
            break
        fi
    fi
    sleep 2
    echo -n "."
done
echo ""

if [ "$CERT_FOUND" -ne 1 ]; then
    echo "==> ERROR: Timeout waiting for ACME certificate issuance!" >&2
    echo "==> Traefik logs:" >&2
    $COMPOSE logs traefik >&2 || true
    echo "==> Legate logs:" >&2
    $COMPOSE logs legate >&2 || true
    echo "==> Mock-CF logs:" >&2
    $COMPOSE logs mock-cf >&2 || true
    exit 1
fi

echo "==> SUCCESS: Traefik obtained signed certificate for app.test.firpic.fr!"
echo "==> Validating Legate audit logs..."
LEGATE_LOGS=$($COMPOSE logs legate)
if ! echo "$LEGATE_LOGS" | grep -q "successfully presented ACME DNS challenge"; then
    echo "==> ERROR: Legate did not log successful challenge presentation" >&2
    exit 1
fi

echo "==> E2E test passed successfully!"
exit 0
