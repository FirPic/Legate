# Configuration Reference

**Legate** supports two configuration mechanisms:
1. **YAML Configuration File** *(Recommended for multi-domain, multi-provider & RBAC environments)*: Loaded via `--config /path/to/config.yaml` or the `CONFIG_FILE` environment variable. Supports native environment variable interpolation `${VAR}`.
2. **Environment Variables** *(For lightweight single-provider deployments)*: 100% backward-compatible single-zone mode.

The application enforces strict **fail-fast** validation: missing required fields or malformed parameters cause the process to exit immediately with an informative error.

---

## 1. YAML Configuration Schema

### Complete Reference Example

```yaml
server:
  port: "8080"
  bind_addr: "0.0.0.0"
  admin_port: "9090"
  admin_bind_addr: "127.0.0.1"
  rate_limit_per_minute: 60
  log_level: "info"
  tls_cert_file: ""          # optional: path to TLS cert file
  tls_key_file: ""           # optional: path to TLS private key file

providers:
  cf-primary:
    type: cloudflare
    api_token: "${CLOUDFLARE_API_TOKEN}"
    zone_id: "${CLOUDFLARE_ZONE_ID}" # optional: skips zone lookup call
    base_url: ""                     # optional: custom API endpoint (defaults to https://api.cloudflare.com/client/v4)

  ionos-corp:
    type: ionos
    api_key: "${IONOS_API_KEY}"      # format: <public_prefix>.<secret>
    base_url: ""                     # optional: defaults to https://api.hosting.ionos.com/dns/v1

  infomaniak-eu:
    type: infomaniak
    api_token: "${INFOMANIAK_API_TOKEN}"
    base_url: ""                     # optional: defaults to https://api.infomaniak.com/1

domains:
  example.com:
    provider: cf-primary
  company.fr:
    provider: ionos-corp
  infra.ch:
    provider: infomaniak-eu

users:
  traefik_dmz:
    password: "${TRAEFIK_PASSWORD}"
    allowed_subdomains:
      - "*.example.com"
      - "*.company.fr"
  caddy_internal:
    password: "${CADDY_PASSWORD}"
    allowed_subdomains:
      - "*.infra.ch"
  admin_full:
    password: "${ADMIN_PASSWORD}"
    allowed_subdomains:
      - "*"
```

---

## 2. YAML Sections Detail

### `server`

| Key | Type | Default | Description |
| :--- | :--- | :---: | :--- |
| `port` | string / int | `"8080"` | Port for the public ACME challenge API (`/present`, `/cleanup`). |
| `bind_addr` | string | `"0.0.0.0"` | Network interface to bind the challenge listener to. |
| `admin_port` | string / int | `"9090"` | Dedicated internal port for operational endpoints (`/healthz`, `/metrics`). |
| `admin_bind_addr` | string | `"127.0.0.1"` | Bind address for admin server. Restricted to localhost by default. |
| `rate_limit_per_minute` | int | `60` | Token-bucket rate limit applied per authenticated user / client IP. |
| `log_level` | string | `"info"` | Log level: `debug`, `info`, `warn`, `error`. |
| `tls_cert_file` | string | `""` | Optional path to PEM certificate file for HTTPS listeners. |
| `tls_key_file` | string | `""` | Optional path to PEM private key file for HTTPS listeners. |

### `providers`

Each entry defines a unique provider instance referenced by key in `domains`:

| Key | Type | Applicable Providers | Description |
| :--- | :--- | :--- | :--- |
| `type` | string | All | Provider type: `cloudflare`, `ionos`, or `infomaniak`. |
| `api_token` | string | `cloudflare`, `infomaniak` | API Bearer token with DNS zone edit permissions. |
| `api_key` | string | `ionos` | IONOS DNS API Key in `<prefix>.<secret>` format. |
| `zone_id` | string | `cloudflare`, `infomaniak` | Optional pre-cached Zone ID (skips dynamic zone lookup). |
| `base_url` | string | All | Optional override of the provider REST API endpoint. |

### `domains`

Maps each apex domain to a configured provider instance:

```yaml
domains:
  <apex-domain>:
    provider: <provider-key>
```

- When an ACME challenge arrives for `_acme-challenge.sub.example.com`, Legate parses the FQDN, extracts the matching domain (`example.com`), and delegates the operation to the associated provider.
- Any request for a domain not declared in `domains` is immediately rejected (`403 Forbidden`).

### `users` (RBAC & Credentials)

Each user entry defines credentials and subdomain authorization rules:

| Key | Type | Description |
| :--- | :--- | :--- |
| `password` | string | Basic Auth password (supports plaintext or environment interpolation `${VAR}`). |
| `allowed_subdomains` | list of strings | List of authorized subdomain glob patterns (e.g. `["*.dmz.example.com", "example.com"]` or `["*"]`). |

#### RBAC Evaluation Rules:
1. `"*"` authorizes any valid subdomain under any domain mapped to the user.
2. `"*.example.com"` authorizes `api.example.com`, `mail.example.com`, etc.
3. Apex domain `"example.com"` must be explicitly listed if the client requests certificates for the root domain itself.

---

## 3. Fallback Environment Variables (Single Provider)

If no `--config` flag or `CONFIG_FILE` variable is provided, Legate operates in single-provider environment variable mode:

| Variable | Required | Default | Description |
| :--- | :---: | :---: | :--- |
| `CLOUDFLARE_API_TOKEN` | Conditional\* | — | Scoped Cloudflare API token (`Zone.DNS:Edit`). |
| `CLOUDFLARE_API_TOKEN_FILE` | Conditional\* | — | File path holding token (ANSSI BP-028 secret mounting). |
| `ALLOWED_DOMAIN` | **Yes** | — | Single domain zone allowed (e.g. `example.com`). |
| `USERS` | Conditional\*\* | — | User accounts (`username:password` or `username:password:subdomains`). |
| `PORT` | No | `8080` | ACME challenge listener port. |
| `BIND_ADDR` | No | `0.0.0.0` | ACME challenge listener bind IP. |
| `ADMIN_PORT` | No | `9090` | Admin & metrics listener port. |
| `ADMIN_BIND_ADDR` | No | `127.0.0.1` | Admin listener bind IP. |
| `RATE_LIMIT_PER_MINUTE` | No | `60` | Requests per minute quota. |
| `LOG_LEVEL` | No | `info` | Logging verbosity (`debug`, `info`, `warn`, `error`). |

*\* Either `CLOUDFLARE_API_TOKEN` or `CLOUDFLARE_API_TOKEN_FILE` is required in env mode.*  
*\*\* At least one valid user account must be configured.*
