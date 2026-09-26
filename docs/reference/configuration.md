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
  # Option A: Direct API token or environment variable interpolation
  cf-primary:
    type: cloudflare
    api_token: "${CLOUDFLARE_API_TOKEN}"
    zone_id: "${CLOUDFLARE_ZONE_ID}" # optional: skips zone lookup call
    base_url: ""                     # optional: custom API endpoint (defaults to https://api.cloudflare.com/client/v4)

  # Option B: Secret file mounted from host (ANSSI BP-028 secret mounting)
  ionos-corp:
    type: ionos
    api_key_file: "/run/secrets/ionos_key"
    base_url: ""                     # optional: defaults to https://api.hosting.ionos.com/dns/v1

  infomaniak-eu:
    type: infomaniak
    api_token_file: "/run/secrets/infomaniak_token"
    base_url: ""                     # optional: defaults to https://api.infomaniak.com/1

domains:
  example.com:
    provider: cf-primary
  company.fr:
    provider: ionos-corp
  infra.ch:
    provider: infomaniak-eu

users:
  # Option A: Direct Argon2id hash
  traefik_dmz:
    password_hash: "$argon2id$v=19$m=65536,t=3,p=2$ZHZ1bmtsZXZhbGlkc2FsdA$YnlF0zPsh8H3R3m5x/l5g8B4o2gC7f6Q9r8u1v2w3x4"
    allowed_subdomains:
      - "*.example.com"
      - "*.company.fr"

  # Option B: Path to mounted secret file containing the Argon2id hash
  caddy_internal:
    password_hash_file: "/run/secrets/caddy_hash"
    allowed_subdomains:
      - "*.infra.ch"

  admin_full:
    password_hash: "$argon2id$v=19$m=65536,t=3,p=2$dGVzdHNhbHQxMjM0NTY3OA$B2WvM8iL+9wKqF2l6X2pY1z8v0s3j4h5g6f7e8d9c0b"
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
| `api_token` | string | `cloudflare`, `infomaniak` | API Bearer token value. Mutually exclusive with `api_token_file`. |
| `api_token_file` | string | `cloudflare`, `infomaniak` | File path containing API Bearer token. Mutually exclusive with `api_token`. |
| `api_key` | string | `ionos` | IONOS DNS API Key (`<prefix>.<secret>`). Mutually exclusive with `api_key_file`. |
| `api_key_file` | string | `ionos` | File path containing IONOS DNS API Key. Mutually exclusive with `api_key`. |
| `zone_id` | string | `cloudflare`, `infomaniak` | Optional pre-cached Zone ID (skips dynamic zone lookup). |
| `base_url` | string | All | Optional override of the provider REST API endpoint (must use HTTPS). |

> [!NOTE]
> Specifying both a direct value and a `_file` path for the same provider is strictly rejected to prevent ambiguity.

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
| `password_hash` | string | RFC 9106 Argon2id hash (`$argon2id$...`). Mutually exclusive with `password_hash_file`. |
| `password_hash_file` | string | File path containing the raw Argon2id hash. Mutually exclusive with `password_hash`. |
| `allowed_subdomains` | list of strings | List of authorized subdomain glob patterns (e.g. `["*.dmz.example.com", "example.com"]` or `["*"]`). |

> [!CAUTION]
> Plaintext passwords in configuration and environment variables are strictly forbidden and rejected at startup.

#### Generating Argon2id Hashes

Legate embeds a native hash generator calibrated to RFC 9106 recommended production parameters ($m=65536 \text{ KiB}, t=3, p=2, \text{salt}=16\text{B}, \text{key}=32\text{B}$):

```bash
# Interactive prompt (recommended - input is masked and never recorded in shell history):
legate hash-password

# Using Podman/Docker container:
podman run --rm -ti ghcr.io/firpic/legate:latest hash-password

# Piped from stdin into secret file:
echo -n "MySuperSecretPassword" | legate hash-password > /run/secrets/traefik_hash
chmod 400 /run/secrets/traefik_hash
```

#### Shell and Compose Escaping Rules:
- **Bash / Zsh**: Always enclose Argon2id hash literals in single quotes (`'...'`). Double quotes (`"..."`) cause the shell to interpret `$argon2id`, `$v`, `$m`, `$p` as environment variables, corrupting the hash.
- **Docker / Podman Compose**: The `compose.yaml` parser interpolates `$` by default. You must escape each `$` as `$$` (e.g. `$$argon2id$$v=19$$m=65536,t=3,p=2$$...`). Using `password_hash_file` completely avoids escaping issues.

#### RBAC Evaluation Rules:
1. `"*"` authorizes any valid subdomain under any domain mapped to the user.
2. `"*.example.com"` authorizes `api.example.com`, `mail.example.com`, etc.
3. Apex domain `"example.com"` must be explicitly listed if the client requests certificates for the root domain itself.

---

## 3. Fallback Environment Variables (Single Provider)

If no `--config` flag or `CONFIG_FILE` variable is provided, Legate operates in single-provider environment variable mode:

| Variable | Required | Default | Description |
| :--- | :---: | :---: | :--- |
| `CLOUDFLARE_API_TOKEN` | Conditional\* | — | Scoped Cloudflare API token (`Zone.DNS:Edit`). Mutually exclusive with `CLOUDFLARE_API_TOKEN_FILE`. |
| `CLOUDFLARE_API_TOKEN_FILE` | Conditional\* | — | File path holding token (ANSSI BP-028 secret mounting). Mutually exclusive with `CLOUDFLARE_API_TOKEN`. |
| `ALLOWED_DOMAIN` | **Yes** | — | Single domain zone allowed (e.g. `example.com`). |
| `USERS` | Conditional\*\* | — | User accounts with Argon2id hashes: `username:argon2id_hash` or `username:argon2id_hash:subdomains`. |
| `USER_<NAME>_PASS` | Conditional\*\* | — | User password as an Argon2id hash (`$argon2id$...`). |
| `USER_<NAME>_PASS_FILE` | Conditional\*\* | — | File path containing the user's Argon2id hash. |
| `USER_<NAME>_SUBDOMAINS` | No | `*` | Comma-separated list of allowed subdomains for `USER_<NAME>`. |
| `PORT` | No | `8080` | ACME challenge listener port. |
| `BIND_ADDR` | No | `0.0.0.0` | ACME challenge listener bind IP. |
| `ADMIN_PORT` | No | `9090` | Admin & metrics listener port. |
| `ADMIN_BIND_ADDR` | No | `127.0.0.1` | Admin listener bind IP. |
| `RATE_LIMIT_PER_MINUTE` | No | `60` | Requests per minute quota. |
| `LOG_LEVEL` | No | `info` | Logging verbosity (`debug`, `info`, `warn`, `error`). |

*\* Either `CLOUDFLARE_API_TOKEN` or `CLOUDFLARE_API_TOKEN_FILE` is required in env mode.*  
*\*\* At least one valid user account must be configured with a valid Argon2id hash.*
