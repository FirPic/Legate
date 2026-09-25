# Legate

[![CI](https://github.com/FirPic/legate/actions/workflows/ci.yaml/badge.svg)](https://github.com/FirPic/legate/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/FirPic/legate)](https://goreportcard.com/report/github.com/FirPic/legate)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Go Version](https://img.shields.io/badge/Go-1.24%2B-blue.svg)](https://golang.org)

**Legate** is a lightweight, zero-dependency ACME DNS-01 challenge gateway written in Go. It securely relays ACME DNS-01 challenges from Lego's [`httpreq`](https://go-acme.github.io/lego/dns/httpreq/) provider (as used by **Traefik**, **Caddy**, and **Lego**) to upstream DNS providers (**Cloudflare**, **IONOS**, **Infomaniak**).

---

## Why Legate?

In hardened, multi-tier network architectures (e.g. DMZ / Internal VLANs conforming to cybersecurity standards such as **ANSSI BP-028 v2.0 MIE**), edge reverse proxies should **never** hold broad DNS API tokens capable of modifying your entire DNS zone.

By placing `legate` in an isolated, restricted security zone:

```text
┌─────────────────────────┐       HTTP Basic Auth         ┌─────────────────────────┐
│     Traefik / Caddy     │ ────────────────────────────> │        Legate           │
│      (DMZ / Edge)       │   POST /present, /cleanup     │  (Restricted Sec Zone)  │
│   No DNS API Tokens     │                               │  Holds DNS API Tokens   │
└─────────────────────────┘                               └─────────────────────────┘
                                                                       │
                                                          ┌────────────┴────────────┐
                                                          │                         │
                                                          v                         v
                                             ┌────────────────────┐  ┌─────────────────────┐
                                             │  Cloudflare DNS    │  │   IONOS / Infomaniak│
                                             └────────────────────┘  └─────────────────────┘
```

- 🔒 **Confined Scope**: Only Legate holds DNS API tokens. Edge reverse proxies only hold local Basic Auth credentials.
- 🛡️ **Strict FQDN Validation**: Rejects any challenge that does not strictly match `_acme-challenge.<allowed_domain>` or its legitimate subdomains. Clients cannot create or alter arbitrary DNS records (such as `A`, `AAAA`, `MX`, or `CNAME`).
- ⚡ **Zero Third-Party Dependencies**: Pure Go standard library (`net/http`, `log/slog`, `crypto/subtle`, `sync`) with official Prometheus metrics export.
- 🔀 **Collision-Proof Concurrency**: Concurrency-safe in-memory tracking pairs each `(fqdn, value)` challenge with its unique DNS record ID. Concurrent certificate renewals across multiple reverse proxies never conflict.
- 🌐 **Multi-Provider**: Single instance can manage ACME challenges across multiple domains and multiple DNS providers simultaneously.

---

## 30-Second Quickstart

Launch the container with Docker or Podman:

```bash
docker run -d \
  --name legate \
  -p 8080:8080 \
  -e CLOUDFLARE_API_TOKEN="your-cloudflare-api-token" \
  -e ALLOWED_DOMAIN="example.com" \
  -e USERS="traefik:StrongPassword123" \
  ghcr.io/firpic/legate:latest
```

Verify service liveness:

```bash
curl -s http://localhost:9090/healthz
# {"allowed_domains":["example.com"],"status":"ok","tracked_records":0}
```

---

## Multi-Provider Configuration (YAML)

For multi-domain setups across multiple DNS providers (**Cloudflare**, **IONOS**, **Infomaniak**), configure using a YAML file with native environment variable expansion (`${VAR}`):

```yaml
server:
  port: "8080"
  bind_addr: "0.0.0.0"
  admin_port: "9090"
  rate_limit_per_minute: 60
  log_level: "info"

providers:
  cf-main:
    type: cloudflare
    api_token: "${CLOUDFLARE_API_TOKEN}"
    zone_id: "${CLOUDFLARE_ZONE_ID}" # optional pre-cached zone

  ionos-prod:
    type: ionos
    api_key: "${IONOS_API_KEY}"      # format: prefix.secret

  infomaniak-corp:
    type: infomaniak
    api_token: "${INFOMANIAK_API_TOKEN}"

domains:
  example.com:
    provider: cf-main
  mon-domaine.fr:
    provider: ionos-prod
  entreprise.ch:
    provider: infomaniak-corp

users:
  traefik_edge:
    password: "${TRAEFIK_PASSWORD}"
    allowed_subdomains: ["*.example.com", "*.mon-domaine.fr"]
  caddy_internal:
    password: "${CADDY_PASSWORD}"
    allowed_subdomains: ["*.entreprise.ch"]
```

Run with configuration file:

```bash
./legate --config /path/to/config.yaml
# Or via environment variable:
CONFIG_FILE=/path/to/config.yaml ./legate
```

> [!NOTE]
> Backward compatibility: If no configuration file is specified, Legate automatically falls back to single-provider environment variable configuration (`CLOUDFLARE_API_TOKEN`, `ALLOWED_DOMAIN`, etc.).

---

## Documentation (Diátaxis Framework)

Our documentation is structured according to the **Diátaxis framework** for clarity and completeness:

| Quadrant | Document | Description |
| :--- | :--- | :--- |
| **🎓 Tutorials** | [Docker Quickstart](docs/tutorials/quickstart-docker.md) | Step-by-step 5-minute hands-on guide with curl and Docker. |
| **🛠️ How-To Guides** | [Traefik Integration](docs/how-to/traefik-httpreq.md) | Practical configuration for Traefik v2 and v3 (`dnsChallenge.provider = httpreq`). |
| | [Scoped Cloudflare Token](docs/how-to/cloudflare-token.md) | How to create a minimal API token restricted to `Zone.DNS:Edit`. |
| | [Hardened Deployment](docs/how-to/systemd-hardening.md) | Deploying as an ANSSI BP-028 MIE systemd unit or Podman Quadlet rootless. |
| **📖 Reference** | [Configuration Reference](docs/reference/configuration.md) | Exhaustive list of environment variables, defaults, and formats. |
| | [API Specification](docs/reference/api.md) | Exact schema for `/present`, `/cleanup`, `/healthz`, and `/metrics`. |
| **💡 Explanation** | [Security Model & Threat Matrix](docs/explanation/security-model.md) | In-depth rationale: separating traffic gateways from credentials gateways. |
| | [Challenge Tracking & Concurrency](docs/explanation/collision-handling.md) | Mathematical tuple tracking and multi-instance collision resolution. |

---

## Features

- **Standard Lego `httpreq` Compatibility**: Implements `POST /present` and `POST /cleanup` in both standard mode (`fqdn` + `value`) and raw mode (`domain` + `token` + `keyAuth`).
- **Multi-Provider Support**: Cloudflare, IONOS, Infomaniak — all in pure Go standard library with no external SDKs.
- **Timing Attack Resistant**: Constant-time authentication comparisons (`crypto/subtle.ConstantTimeCompare`) with dummy hash evaluation against user enumeration.
- **RFC 1123 Strict Domain Validation**: Forbids CRLF, null bytes, backslashes, path traversal, and domain spoofing.
- **Production Observability**:
  - Structured JSON logging via standard Go `log/slog`.
  - Prometheus metrics on `/metrics` (`acme_dns_challenges_total`, `acme_dns_active_records`, `acme_dns_provider_requests_total`, `acme_dns_request_duration_seconds`).
  - Liveness and readiness probe on `/healthz`.
  - Graceful shutdown handling `SIGINT` and `SIGTERM`.

---

## Community & Contributing

We welcome contributions! Please review:
- [CONTRIBUTING.md](CONTRIBUTING.md) for development workflows, testing guidelines, and code conventions.
- [SECURITY.md](SECURITY.md) for vulnerability disclosure and reporting procedures.

---

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).

Copyright (C) 2026 FirPic
