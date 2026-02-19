# Integration Tests (Keycloak)

Runs the OIDC library against a real Keycloak instance in Docker.

## Prerequisites

- Docker with `docker compose`
- `curl` (for health check polling)
- Port 18080 free (Keycloak)

## Usage

```sh
./tests/integration/run.sh
```

This will:
1. Start Keycloak in Docker with a pre-configured test realm
2. Wait for Keycloak to be ready
3. Run the integration tests
4. Tear down the container (even on failure/Ctrl+C)

## Manual testing

If you want to iterate on tests without restarting Keycloak each time:

```sh
# Start Keycloak (leave it running)
docker compose -f tests/integration/docker-compose.yml up -d

# Wait for it to be ready, then run tests as many times as needed
cargo test --test keycloak_integration -- --ignored --test-threads=1

# When done
docker compose -f tests/integration/docker-compose.yml down --volumes --remove-orphans
```

## Test realm configuration

- Realm: `test-realm`
- Client: `test-client` / `test-client-secret` (confidential, authorization code flow)
- Redirect URI: `http://localhost:19090/oidc/callback` (nothing listens; redirects are intercepted)
- User: `testuser` / `testpassword` (email: `testuser@example.com`)

## Troubleshooting

**Keycloak won't start:** Check if port 18080 is already in use (`lsof -i :18080`).

**Realm not found:** The realm import may have failed. Check logs:
```sh
docker compose -f tests/integration/docker-compose.yml logs keycloak
```

**Tests hang:** Ensure Keycloak is healthy: `curl -s http://localhost:18080/health/ready`
