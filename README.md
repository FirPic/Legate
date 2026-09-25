# acme-dns-httpreq-proxy

[![CI](https://github.com/FirPic/acme-dns-httpreq-proxy/actions/workflows/ci.yaml/badge.svg)](https://github.com/FirPic/acme-dns-httpreq-proxy/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/FirPic/acme-dns-httpreq-proxy)](https://goreportcard.com/report/github.com/FirPic/acme-dns-httpreq-proxy)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.24%2B-blue.svg)](https://golang.org)

A lightweight, zero-dependency, cloud-native HTTP proxy written in Go that securely relays ACME DNS-01 challenges from Lego's [`httpreq`](https://go-acme.github.io/lego/dns/httpreq/) provider (as used by **Traefik**, **Caddy**, and **Lego**) to upstream DNS providers (**Cloudflare**, **IONOS**, **Infomaniak**).

---

## Why this Proxy?

In hardened, multi-tier network architectures (e.g. DMZ / Internal VLANs conforming to cybersecurity standards such as **ANSSI BP-028 v2.0 MIE**), edge reverse proxies should **never** hold broad Cloudflare API tokens capable of modifying your entire DNS zone.

By placing `acme-dns-httpreq-proxy` in an isolated, restricted security zone:

```text
┌─────────────────────────┐       HTTP Basic Auth         ┌─────────────────────────┐
│     Traefik / Caddy     │ ────────────────────────────> │ acme-dns-httpreq-proxy  │
│      (DMZ / Edge)       │   POST /present, /cleanup     │  (Restricted Sec Zone)  │
│   No Cloudflare Token   │                               │ Holds Cloudflare Token  │
└─────────────────────────┘                               └─────────────────────────┘
                                                                       │
                                                                       │ Cloudflare API v4
                                                                       v
                                                          ┌─────────────────────────┐
                                                          │   Cloudflare DNS Zone   │
                                                          └─────────────────────────┘
```

- 🔒 **Confined Scope**: Only the proxy holds the Cloudflare API token. Edge reverse proxies only hold local Basic Auth credentials.
- 🛡️ **Strict FQDN Validation**: Rejects any challenge that does not strictly match `_acme-challenge.<allowed_domain>` or its legitimate subdomains. Traefik cannot create or alter arbitrary DNS records (such as `A`, `AAAA`, `MX`, or `CNAME`).
- ⚡ **Zero Third-Party Dependencies**: Pure Go standard library (`net/http`, `log/slog`, `crypto/subtle`, `sync`) with official Prometheus metrics export.
- 🔀 **Collision-Proof Concurrency**: Concurrency-safe in-memory tracking pairs each `(fqdn, value)` challenge with its unique Cloudflare record ID. Concurrent certificate renewals across multiple reverse proxies never conflict or delete each other's records.

---

## 30-Second Quickstart

Launch the container with Docker or Podman:

```bash
docker run -d \
  --name acme-dns-proxy \
  -p 8080:8080 \
  -e CLOUDFLARE_API_TOKEN="your-cloudflare-api-token" \
  -e ALLOWED_DOMAIN="example.com" \
  -e USERS="traefik:StrongPassword123" \
  ghcr.io/firpic/acme-dns-httpreq-proxy:latest
```

Verify service liveness:

```bash
curl -s http://localhost:8080/healthz
# {"allowed_domain":"example.com","allowed_domains":["example.com"],"status":"ok","tracked_records":0}
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
./acme-dns-proxy --config /path/to/config.yaml
# Or via environment variable:
CONFIG_FILE=/path/to/config.yaml ./acme-dns-proxy
```

> [!NOTE]
> Backward compatibility: If no configuration file is specified, `acme-dns-httpreq-proxy` automatically falls back to single-provider environment variable configuration (`CLOUDFLARE_API_TOKEN`, `ALLOWED_DOMAIN`, etc.).

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
- **Timing Attack Resistant**: Constant-time authentication comparisons (`crypto/subtle.ConstantTimeCompare`) with dummy hash evaluation against user enumeration.
- **RFC 1123 Strict Domain Validation**: Forbids CRLF, null bytes, backslashes, path traversal, and domain spoofing.
- **Production Observability**:
  - Structured JSON logging via standard Go `log/slog`.
  - Prometheus metrics on `/metrics` (`acme_dns_challenges_total`, `acme_dns_active_records`, `acme_dns_cloudflare_requests_total`, `acme_dns_request_duration_seconds`).
  - Liveness and readiness probe on `/healthz`.
  - Graceful shutdown handling `SIGINT` and `SIGTERM`.

---

## Community & Contributing

We welcome contributions! Please review:
- [CONTRIBUTING.md](CONTRIBUTING.md) for development workflows, testing guidelines, and code conventions.
- [SECURITY.md](SECURITY.md) for vulnerability disclosure and reporting procedures.

---

## License

This project is licensed under the [MIT License](LICENSE).
