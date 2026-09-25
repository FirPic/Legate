# acme-dns-httpreq-proxy

[![CI](https://github.com/FirPic/acme-dns-httpreq-proxy/actions/workflows/ci.yaml/badge.svg)](https://github.com/FirPic/acme-dns-httpreq-proxy/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/FirPic/acme-dns-httpreq-proxy)](https://goreportcard.com/report/github.com/FirPic/acme-dns-httpreq-proxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A lightweight, zero-dependency, secure HTTP proxy written in Go 1.24+ designed to relay ACME DNS-01 challenges from Lego's [`httpreq`](https://go-acme.github.io/lego/dns/httpreq/) provider (as used by Traefik, Caddy, or standalone Lego) to the Cloudflare API v4.

---

## Why this proxy?

In hardened, multi-tier infrastructure (e.g. DMZ / Internal VLANs conforming to strict security standards such as ANSSI BP-028), edge reverse proxies (such as Traefik) should **never** hold broad Cloudflare API tokens with write access to your entire DNS zone.

By placing `acme-dns-httpreq-proxy` in a restricted security zone:
1. **Confined Scope**: Only this proxy holds the `CLOUDFLARE_API_TOKEN`.
2. **Strict FQDN Validation**: Rejects any challenge that does not match `_acme-challenge.<allowed_domain>` or its legitimate subdomains. Traefik cannot create or overwrite arbitrary DNS records.
3. **No Third-Party Vulnerabilities**: Built strictly with the Go standard library (`net/http`, `log/slog`, `crypto/subtle`). Zero external dependencies.
4. **Isolated Cleanup Tracking**: Concurrency-safe record tracking ensures that concurrent renewals by multiple Traefik instances only delete their own corresponding TXT records.

---

## Features

- **Standard Lego `httpreq` Provider Compatibility**:
  - Implements `POST /present` and `POST /cleanup`.
  - Supports both standard mode (`fqdn`, `value`) and RAW mode (`domain`, `token`, `keyAuth`).
- **Strict Security & Validation**:
  - Strict FQDN checking against `ALLOWED_DOMAIN` (RFC 1123 label enforcement, suffix injection prevention).
  - Constant-time Basic Authentication (`crypto/subtle.ConstantTimeCompare`) resistant to timing attacks.
  - Request body limits to mitigate denial-of-service (DoS) attempts.
- **Resilient TXT Record Tracking**:
  - Thread-safe in-memory tracker (`sync.RWMutex`) pairing `(fqdn, value)` with Cloudflare `record_id`.
  - Cloudflare query fallback if proxy restarts during an in-flight ACME challenge.
- **Production Observability**:
  - Structured JSON logging (`log/slog`).
  - Unauthenticated `GET /healthz` endpoint for monitoring, liveness, and readiness probes.
  - Graceful shutdown on `SIGINT` / `SIGTERM`.

---

## Configuration

The proxy is configured entirely via environment variables:

| Variable | Required | Default | Description |
| :--- | :---: | :---: | :--- |
| `CLOUDFLARE_API_TOKEN` | **Yes** | — | Cloudflare API token with `Zone.DNS:Edit` permissions. |
| `ALLOWED_DOMAIN` | **Yes** | — | The root apex domain allowed for ACME challenges (e.g. `firpic.fr`). |
| `USERS` | **Yes\*** | — | Comma-separated `user:pass` pairs or JSON object (see below). |
| `PORT` | No | `8080` | Port to listen on. |
| `BIND_ADDR` | No | `0.0.0.0` | Host or IP to bind the listener to. |
| `CLOUDFLARE_ZONE_ID` | No | *(Auto)* | Pre-configured Cloudflare Zone ID (skips API zone lookup). |
| `LOG_LEVEL` | No | `info` | Logging verbosity (`debug`, `info`, `warn`, `error`). |

*\* Note: You can either set `USERS` or provide individual user passwords via `USER_<NAME>_PASS`.*

### User Authentication Formats

You can define authorized users in three ways:

1. **Comma-separated string**:
   ```bash
   USERS="traefik_dmz:SecretPass1,traefik_infra:SecretPass2"
   ```

2. **JSON map**:
   ```bash
   USERS='{"traefik_dmz":"SecretPass1","traefik_infra":"SecretPass2"}'
   ```

3. **Dedicated environment variables**:
   ```bash
   USER_TRAEFIK_DMZ_PASS="SecretPass1"
   USER_TRAEFIK_INFRA_PASS="SecretPass2"
   ```

---

## Quick Start

### Running with Docker / Podman

```bash
docker run -d \
  --name acme-dns-httpreq-proxy \
  -p 8080:8080 \
  -e CLOUDFLARE_API_TOKEN="your-cloudflare-token" \
  -e ALLOWED_DOMAIN="firpic.fr" \
  -e USERS="traefik:StrongPassword123" \
  ghcr.io/firpic/acme-dns-httpreq-proxy:latest
```

### Running from Binary

```bash
export CLOUDFLARE_API_TOKEN="your-cloudflare-token"
export ALLOWED_DOMAIN="firpic.fr"
export USERS="traefik:StrongPassword123"
export PORT="8080"

./acme-dns-httpreq-proxy
```

---

## Traefik Integration

Configure Traefik to use the Lego `httpreq` provider pointing to this proxy:

### `traefik.yaml`

```yaml
certificatesResolvers:
  cloudflare:
    acme:
      email: admin@firpic.fr
      storage: /etc/traefik/acme/acme.json
      dnsChallenge:
        provider: httpreq
        delayBeforeCheck: 10
        resolvers:
          - "1.1.1.1:53"
          - "8.8.8.8:53"
```

### Traefik Environment Variables

In Traefik's systemd unit or container environment:

```ini
HTTPREQ_ENDPOINT=http://10.53.20.15:8080
HTTPREQ_USERNAME=traefik
HTTPREQ_PASSWORD=StrongPassword123
HTTPREQ_HTTP_TIMEOUT=30
```

Traefik will send HTTP requests to:
- `POST http://10.53.20.15:8080/present`
- `POST http://10.53.20.15:8080/cleanup`

---

## API Reference

### 1. `GET /healthz`

Health and readiness probe.

```bash
curl -s http://127.0.0.1:8080/healthz
```

**Response (200 OK):**
```json
{
  "allowed_domain": "firpic.fr",
  "status": "ok",
  "tracked_records": 0
}
```

---

### 2. `POST /present`

Creates an ACME challenge TXT record on Cloudflare. Requires HTTP Basic Authentication.

```bash
curl -i -X POST http://127.0.0.1:8080/present \
  -u "traefik:StrongPassword123" \
  -H "Content-Type: application/json" \
  -d '{
    "fqdn": "_acme-challenge.traefik.firpic.fr.",
    "value": "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM"
  }'
```

**Response (200 OK):**
```json
{
  "status": "success",
  "action": "present",
  "fqdn": "_acme-challenge.traefik.firpic.fr",
  "record_id": "372e67954025e0ba6aaa6d586b9e0b59"
}
```

---

### 3. `POST /cleanup`

Deletes the ACME challenge TXT record. Requires HTTP Basic Authentication.

```bash
curl -i -X POST http://127.0.0.1:8080/cleanup \
  -u "traefik:StrongPassword123" \
  -H "Content-Type: application/json" \
  -d '{
    "fqdn": "_acme-challenge.traefik.firpic.fr.",
    "value": "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM"
  }'
```

**Response (200 OK):**
```json
{
  "status": "success",
  "action": "cleanup",
  "fqdn": "_acme-challenge.traefik.firpic.fr",
  "record_id": "372e67954025e0ba6aaa6d586b9e0b59"
}
```

---

## Error Handling & Status Codes

| Status Code | Description |
| :--- | :--- |
| `200 OK` | Record successfully created or deleted. |
| `400 Bad Request` | Malformed JSON or invalid challenge token. |
| `401 Unauthorized` | Invalid or missing Basic Auth credentials. |
| `403 Forbidden` | The requested FQDN does not match `_acme-challenge.<allowed_domain>`. |
| `502 Bad Gateway` | Upstream Cloudflare API returned an error or is unreachable. |

---

## Development & Testing

Run all unit tests with race detection:

```bash
go test -v -race ./...
```

Run test suite with coverage:

```bash
go test -v -race -coverprofile=coverage.txt -covermode=atomic ./...
go tool cover -func=coverage.txt
```

---

## Security Hardening Details

- **Minimal Container Image**: Final container is built `FROM scratch` with only CA certificates and the compiled static binary (`CGO_ENABLED=0`).
- **Non-Root Execution**: Runs as unprivileged user `nobody:nobody` (`UID 65534`).
- **Timing Attack Resistance**: Uses `crypto/subtle.ConstantTimeCompare` for password verification and evaluates dummy hashes even on non-existent usernames.
- **Strict RFC 1123 Label Parsing**: Prevents newline injections, CRLF headers, null byte injections, or domain traversal attempts.

---

## License

This project is licensed under the [MIT License](LICENSE).
