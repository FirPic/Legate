# Configuration Reference

All settings for `acme-dns-httpreq-proxy` are configured through environment variables or file-based secret mounts. The application adheres to fail-fast principles: missing required variables or malformed parameters cause the process to exit immediately with code 1 during startup.

---

## Environment Variables

| Variable | Type | Required | Default | Description |
| :--- | :--- | :---: | :---: | :--- |
| `CLOUDFLARE_API_TOKEN` | String (Secret) | **Conditional\*** | — | Scoped Cloudflare API token with `Zone.DNS:Edit` permissions. |
| `CLOUDFLARE_API_TOKEN_FILE` | String (Path) | **Conditional\*** | — | Path to file containing Cloudflare API token (ANSSI BP-028 secret mounting). |
| `ALLOWED_DOMAIN` | String | **Yes** | — | Apex domain allowed for ACME challenges (e.g. `example.com`). |
| `USERS` | String | **Conditional\*\*** | — | Authorized client credentials and RBAC rules (JSON or comma-delimited). |
| `USER_<NAME>_PASS` | String (Secret) | **Conditional\*\*** | — | Password for a specific user `<NAME>` (e.g. `USER_TRAEFIK_DMZ_PASS`). |
| `USER_<NAME>_SUBDOMAINS` | String | No | `*` | Comma-separated allowed subdomains for `<NAME>` (e.g. `*.dmz.firpic.fr,dmz.firpic.fr`). |
| `PORT` | Integer | No | `8080` | Port for the public ACME challenge API (`/present`, `/cleanup`). |
| `BIND_ADDR` | String | No | `0.0.0.0` | Host interface or IP address to bind the challenge listener to. |
| `ADMIN_PORT` | Integer | No | `9090` | Dedicated internal port for operational endpoints (`/healthz`, `/metrics`). |
| `ADMIN_BIND_ADDR` | String | No | `127.0.0.1` | Bind address for the admin server (defaults to localhost). |
| `RATE_LIMIT_PER_MINUTE` | Integer | No | `60` | Maximum allowed challenge requests per minute per client IP / user. |
| `CLOUDFLARE_ZONE_ID` | String | No | *(Auto)* | Pre-configured Cloudflare Zone ID (skips API zone lookup). |
| `LOG_LEVEL` | String | No | `info` | Minimum log verbosity level: `debug`, `info`, `warn`, `error`. |

*\* Either `CLOUDFLARE_API_TOKEN` or `CLOUDFLARE_API_TOKEN_FILE` must be provided.*  
*\*\* At least one valid user must be configured, either through `USERS` or through `USER_<NAME>_PASS`.*

---

## RBAC and Authorized Users (`USERS`)

User authentication credentials and their permitted subdomain boundaries can be supplied in three interchangeable formats:

### 1. Structured JSON (Recommended for RBAC)
Allows binding specific reverse proxies to restricted subdomain patterns:
```json
{
  "traefik_dmz": {
    "password": "StrongPassword123",
    "allowed_subdomains": ["*.dmz.firpic.fr", "dmz.firpic.fr"]
  },
  "traefik_infra": {
    "password": "AnotherStrongPassword456",
    "allowed_subdomains": ["*.infra.firpic.fr", "infra.firpic.fr"]
  },
  "admin": {
    "password": "AdminPassword789",
    "allowed_subdomains": ["*"]
  }
}
```

### 2. Comma-Separated Pairs with Subdomains
Format: `username:password:subdomain1;subdomain2,...`
```bash
USERS="traefik_dmz:SecretPass1:*.dmz.firpic.fr;dmz.firpic.fr,traefik_infra:SecretPass2:*"
```

### 3. Individual Environment Variables
Ideal for Docker Secrets, Kubernetes, or HashiCorp Vault Agent templates:
```bash
USER_TRAEFIK_DMZ_PASS="SecretPass1"
USER_TRAEFIK_DMZ_SUBDOMAINS="*.dmz.firpic.fr,dmz.firpic.fr"

USER_TRAEFIK_INFRA_PASSWORD="SecretPass2"
USER_TRAEFIK_INFRA_SUBDOMAINS="*"
```

---

## Detailed Variable Specifications

### `CLOUDFLARE_API_TOKEN_FILE`
- **Description:** Path to a file on disk (typically mounted in tmpfs at `/run/secrets/cf_token`) holding the token.
- **Security:** In accordance with ANSSI BP-028 recommendations, file-based secrets prevent accidental token leakage via process environment inspection (`/proc/$PID/environ`).

### `ADMIN_PORT` & `ADMIN_BIND_ADDR`
- **Description:** Binds a distinct HTTP listener exclusively serving `/healthz` and `/metrics`.
- **Default:** `127.0.0.1:9090`.
- **Security:** Separating the admin port prevents external or DMZ network clients from scraping Prometheus telemetry or probe endpoints.

### `RATE_LIMIT_PER_MINUTE`
- **Description:** Token bucket rate limiter preventing upstream Cloudflare API quota exhaustion.
- **Default:** `60` requests per minute.
- **Action:** Requests exceeding the burst limit receive `429 Too Many Requests` with a `Retry-After: 1` header.
