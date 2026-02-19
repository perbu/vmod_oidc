#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cleanup() {
    echo "Tearing down Keycloak..."
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" down --volumes --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

echo "Starting Keycloak..."
docker compose -f "$SCRIPT_DIR/docker-compose.yml" up -d

echo "Waiting for Keycloak to be ready (up to 120s)..."
TIMEOUT=120
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    if curl -sf http://localhost:18080/health/ready > /dev/null 2>&1; then
        echo "Keycloak is ready (${ELAPSED}s)"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "ERROR: Keycloak did not become ready within ${TIMEOUT}s"
    echo "Container logs:"
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" logs keycloak
    exit 1
fi

# Verify the test realm's discovery endpoint is accessible
DISCOVERY_URL="http://localhost:18080/realms/test-realm/.well-known/openid-configuration"
echo "Verifying realm discovery at $DISCOVERY_URL ..."
if ! curl -sf "$DISCOVERY_URL" > /dev/null; then
    echo "ERROR: Realm discovery endpoint not available"
    echo "The realm import may have failed. Check container logs:"
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" logs keycloak
    exit 1
fi
echo "Realm discovery OK"

echo ""
echo "Running integration tests..."
cd "$PROJECT_DIR"
cargo test --test keycloak_integration -- --ignored --test-threads=1

echo ""
echo "All integration tests passed!"
