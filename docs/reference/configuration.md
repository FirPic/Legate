# Configuration Reference

All settings for `acme-dns-httpreq-proxy` are configured through environment variables. The application adheres to fail-fast principles: missing required variables or malformed parameters cause the process to exit immediately with code 1 during startup.

---

## Environment Variables

| Variable | Type | Required | Default | Description |
| :--- | :--- | :---: | :---: | :--- |
| `CLOUDFLARE_API_TOKEN` | String (Secret) | **Yes** | — | Scoped Cloudflare API token with `Zone.DNS:Edit` permissions. |
| `ALLOWED_DOMAIN` | String | **Yes** | — | Apex domain allowed for ACME challenges (e.g. `example.com`). |
| `USERS` | String | **Conditional\*** | — | Authorized client credentials for Basic Authentication. |
| `USER_<NAME>_PASS` | String (Secret) | **Conditional\*** | — | Password for a specific user `<NAME>` (e.g. `USER_TRAEFIK_DMZ_PASS`). |
| `PORT` | Integer | No | `8080` | Port to listen on (1–65535). |
| `BIND_ADDR` | String | No | `0.0.0.0` | Host interface or IP address to bind to (e.g. `127.0.0.1` or `10.53.20.15`). |
| `CLOUDFLARE_ZONE_ID` | String | No | *(Auto)* | Pre-configured Cloudflare Zone ID (skips API zone lookup). |
| `LOG_LEVEL` | String | No | `info` | Minimum log verbosity level: `debug`, `info`, `warn`, `error`. |

*\* At least one valid user must be configured, either through `USERS` or through one or more `USER_<NAME>_PASS` variables.*

---

## Detailed Variable Specifications

### `CLOUDFLARE_API_TOKEN`
- **Description:** A custom API token generated in the Cloudflare dashboard.
- **Required permissions:** `Zone` -> `DNS` -> `Edit`.
- **Validation:** Must be a non-empty string.
- **Security:** Treat as a critical secret. Never commit to source control.

### `ALLOWED_DOMAIN`
- **Description:** The root domain zone that this proxy instance is authorized to modify.
- **Format:** Fully qualified apex domain name without protocol or paths (e.g. `example.com` or `firpic.fr`). Trailing dot is automatically stripped.
- **Validation:** Must not contain spaces, wildcards, path traversal characters (`/`, `\`, `..`), or URL characters. All incoming challenge requests must target `_acme-challenge.<ALLOWED_DOMAIN>` or `_acme-challenge.<subdomain>.<ALLOWED_DOMAIN>`.

### `PORT`
- **Description:** The TCP port on which the HTTP server listens.
- **Range:** Must be an integer between `1` and `65535`.
- **Default:** `8080`.

### `BIND_ADDR`
- **Description:** Network address for the HTTP listener socket.
- **Default:** `0.0.0.0` (all network interfaces).
- **Hardening Recommendation:** In hardened or multi-homed environments, bind specifically to an internal private IP (e.g. `10.53.20.15` or `127.0.0.1`).

### `CLOUDFLARE_ZONE_ID`
- **Description:** The hexadecimal 32-character Cloudflare Zone ID for `ALLOWED_DOMAIN`.
- **Default:** Empty. When not provided, the proxy automatically queries `GET /zones?name=<ALLOWED_DOMAIN>` during startup or upon the first challenge and caches the result.
- **Use case:** Supplying this variable avoids an extra Cloudflare API lookup and speeds up cold starts.

### `LOG_LEVEL`
- **Description:** Sets the severity threshold for structured JSON logging.
- **Allowed values:**
  - `debug`: Detailed logging including request headers and Cloudflare API calls.
  - `info` *(default)*: Standard operational events (challenge creation, deletions, startup).
  - `warn`: Authorization failures, invalid challenge attempts, fallback recoveries.
  - `error`: Fatal DNS failures, Cloudflare API errors, unrecoverable states.

---

## Specifying Authorized Users (`USERS`)

User authentication credentials can be supplied in three interchangeable formats:

### 1. Comma-Separated Pairs
Ideal for simple container deployments:
```bash
USERS="traefik_dmz:SecretPass1,traefik_infra:SecretPass2"
```

### 2. JSON Map
Ideal when passing secrets serialized as JSON:
```bash
USERS='{"traefik_dmz":"SecretPass1","traefik_infra":"SecretPass2"}'
```

### 3. Individual Prefix Environment Variables
Ideal for Docker Secrets, Kubernetes ConfigMaps, or HashiCorp Vault integrations where individual secrets are mapped to separate environment keys:
```bash
USER_TRAEFIK_DMZ_PASS="SecretPass1"
USER_TRAEFIK_INFRA_PASSWORD="SecretPass2"
```

*Note: Usernames are normalized to lowercase. Authentication uses constant-time string comparisons (`crypto/subtle.ConstantTimeCompare`) to prevent timing side-channel attacks.*
