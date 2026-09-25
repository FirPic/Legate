<div align="center">

# Legate

**Lightweight, Zero-Dependency ACME DNS-01 Challenge Gateway**

[![CI](https://github.com/FirPic/legate/actions/workflows/ci.yaml/badge.svg)](https://github.com/FirPic/legate/actions/workflows/ci.yaml)
[![Go Report Card](https://goreportcard.com/badge/github.com/FirPic/legate)](https://goreportcard.com/report/github.com/FirPic/legate)
[![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8?logo=go&logoColor=white)](https://golang.org)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![OCI Container](https://img.shields.io/badge/Container-ghcr.io%2Ffirpic%2Flegate-892CA0?logo=podman&logoColor=white)](https://github.com/FirPic/legate/pkgs/container/legate)
[![Security Hardened](https://img.shields.io/badge/Security-ANSSI_BP--028_MIE-success.svg)](docs/explanation/security-model.md)

<p align="center">
  <a href="#why-legate">Why Legate?</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#supported-providers">Supported Providers</a> •
  <a href="#quickstart">Quickstart</a> •
  <a href="#production-stack-traefik--legate">Production Stack</a> •
  <a href="#configuration">Configuration</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#security">Security</a>
</p>

</div>

---

**Legate** is a lightweight, zero-dependency ACME DNS-01 challenge gateway written in Go. It securely bridges reverse proxies (**Traefik**, **Caddy**, or the **Lego** CLI via Lego's standard [`httpreq`](https://go-acme.github.io/lego/dns/httpreq/) webhook) with upstream DNS providers (**Cloudflare**, **IONOS**, **Infomaniak**).

---

## Why Legate?

In hardened, multi-tier architectures (such as infrastructure conforming to **ANSSI BP-028 v2.0 MIE**), edge reverse proxies reside in DMZ networks facing untrusted public traffic. 

Configuring reverse proxies with direct DNS API credentials introduces a critical architectural vulnerability: **if the edge proxy is compromised via an RCE or directory traversal, attackers gain global DNS tokens capable of altering apex `A`, `AAAA`, `MX`, and `SPF` records.**

| Traditional Setup | With Legate |
| :--- | :--- |
| Edge proxies hold global DNS API tokens in DMZ | Only Legate holds DNS API tokens, isolated in a restricted zone |
| Compromise of edge proxy results in full domain hijacking | Edge proxies only hold local Basic Auth scoped strictly to ACME TXT records |
| No restriction on DNS record types manipulated | Legate strictly permits only `_acme-challenge.<zone>` TXT records |
| Race conditions when multiple proxies renew certificates | Concurrency-safe tuple tracking pairs each challenge with its provider record |
| Heavy dependencies and third-party SDK bloat | Pure Go standard library + Prometheus metrics, static scratch container |

---

## Architecture

```text
┌─────────────────────────────────┐
│     DMZ / Edge Network          │
│                                 │
│      ┌───────────────────┐      │
│      │  Traefik / Caddy  │      │
│      │ No DNS API Tokens │      │
│      └─────────┬─────────┘      │
└────────────────┼────────────────┘
                 │ HTTP Basic Auth
                 │ POST /present, /cleanup (16 KiB limit)
                 │ Strictly confined to _acme-challenge.<zone>
                 v
┌─────────────────────────────────┐
│   Restricted Security Zone      │
│                                 │
│      ┌───────────────────┐      │
│      │      Legate       │      │
│      │ Holds DNS Tokens  │      │
│      └─────────┬─────────┘      │
└────────────────┼────────────────┘
                 │ Outbound HTTPS (REST APIs)
                 │ Cloudflare / IONOS / Infomaniak
                 v
┌─────────────────────────────────────────────────────────┐
│                 Upstream DNS Providers                  │
│                                                         │
│   ┌───────────────┐  ┌───────────────┐  ┌───────────┐   │
│   │  Cloudflare   │  │   IONOS DNS   │  │Infomaniak │   │
│   └───────────────┘  └───────────────┘  └───────────┘   │
└─────────────────────────────────────────────────────────┘
```

- **Authentication & RBAC**: Edge reverse proxies authenticate using HTTP Basic Auth. User accounts can be scoped to specific subdomains (e.g. `*.dmz.example.com`).
- **Input Validation**: Strict RFC 1123 domain validation and RFC 8555 base64url challenge character verification.
- **Port Isolation**: ACME challenge webhook on port `:8080`; Prometheus `/metrics` and `/healthz` isolated on administrative port `:9090`.

---

## Supported Providers

Legate implements provider integrations using the pure Go standard library with zero external vendor SDKs:

| Provider | Authentication | Dynamic Zone Discovery | Multi-Domain Routing | Granular RBAC |
| :--- | :--- | :---: | :---: | :---: |
| **Cloudflare** | Bearer API Token (`Zone.DNS:Edit`) | Yes (Auto / Zone ID cache) | Yes | Yes |
| **IONOS** | API Key (`<prefix>.<secret>`) | Yes (Auto-lookup) | Yes | Yes |
| **Infomaniak** | Bearer API Token | Yes (Auto-lookup) | Yes | Yes |

---

## Quickstart

Run a standalone Legate container with Podman:

```bash
podman run -d \
  --name legate \
  -p 8080:8080 \
  -p 127.0.0.1:9090:9090 \
  -e CLOUDFLARE_API_TOKEN="your-cloudflare-api-token" \
  -e ALLOWED_DOMAIN="example.com" \
  -e USERS="traefik:StrongPassword123" \
  ghcr.io/firpic/legate:latest
```

Verify operational readiness:

```bash
curl -s http://127.0.0.1:9090/healthz
# {"domains_count":1,"status":"ok","tracked_records":0}
```

---

## Production Stack: Traefik + Legate

Here is a turnkey, multi-network `compose.yaml` demonstrating network compartmentalization with Podman: Traefik sits in an external ingress network, while Legate runs inside an isolated internal backend network.

```yaml
services:
  traefik:
    image: traefik:v3.1
    container_name: traefik
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    networks:
      - edge-network
      - security-zone
    environment:
      - HTTPREQ_ENDPOINT=http://legate:8080
      - HTTPREQ_USERNAME=traefik_dmz
      - HTTPREQ_PASSWORD=${TRAEFIK_LEGATE_PASSWORD}
      - HTTPREQ_HTTP_TIMEOUT=30
    volumes:
      - /run/podman/podman.sock:/var/run/docker.sock:ro
      - ./traefik.yaml:/etc/traefik/traefik.yaml:ro
      - ./acme.json:/etc/traefik/acme/acme.json

  legate:
    image: ghcr.io/firpic/legate:latest
    container_name: legate
    restart: unless-stopped
    networks:
      - security-zone
    ports:
      - "127.0.0.1:9090:9090" # Admin probe & metrics on host loopback only
    volumes:
      - ./legate.yaml:/etc/legate/config.yaml:ro
    environment:
      - CONFIG_FILE=/etc/legate/config.yaml
      - CLOUDFLARE_API_TOKEN=${CLOUDFLARE_API_TOKEN}
      - TRAEFIK_LEGATE_PASSWORD=${TRAEFIK_LEGATE_PASSWORD}

networks:
  edge-network:
    driver: bridge
  security-zone:
    internal: true # Isolated backend network with no direct ingress
```

Launch the stack:

```bash
podman compose up -d
```

In your `traefik.yaml`:

```yaml
certificatesResolvers:
  legateResolver:
    acme:
      email: admin@example.com
      storage: /etc/traefik/acme/acme.json
      dnsChallenge:
        provider: httpreq
        delayBeforeCheck: 10
        resolvers:
          - "1.1.1.1:53"
          - "8.8.8.8:53"
```

---

## Configuration

For production multi-domain setups across multiple DNS providers, configure Legate using a YAML file with native environment variable expansion (`${VAR}`):

```yaml
server:
  port: "8080"
  bind_addr: "0.0.0.0"
  admin_port: "9090"
  admin_bind_addr: "127.0.0.1"
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
  traefik_dmz:
    password: "${TRAEFIK_PASSWORD}"
    allowed_subdomains:
      - "*.example.com"
      - "*.mon-domaine.fr"
  caddy_internal:
    password: "${CADDY_PASSWORD}"
    allowed_subdomains:
      - "*.entreprise.ch"
  admin_full:
    password: "${ADMIN_PASSWORD}"
    allowed_subdomains:
      - "*"
```

Launch with configuration:

```bash
./legate --config /path/to/config.yaml
# Or using the environment variable:
CONFIG_FILE=/path/to/config.yaml ./legate
```

---

## Documentation

Our documentation is structured according to the **Diátaxis framework**:

| Quadrant | Document | Description |
| :--- | :--- | :--- |
| **Tutorials** | [Podman Quickstart](docs/tutorials/quickstart-podman.md) | Step-by-step hands-on guide with curl and Podman. |
| **How-To Guides** | [Traefik Integration](docs/how-to/traefik-httpreq.md) | Production configuration for Traefik v2/v3 with `httpreq`. |
| | [Scoped Cloudflare Token](docs/how-to/cloudflare-token.md) | Creating minimal API tokens restricted to `Zone.DNS:Edit`. |
| | [Hardened Deployment](docs/how-to/systemd-hardening.md) | Deploying as an ANSSI BP-028 MIE systemd unit or Podman Quadlet. |
| **Reference** | [Configuration Reference](docs/reference/configuration.md) | Complete YAML schema, environment variables, and RBAC rules. |
| | [API Specification](docs/reference/api.md) | JSON schemas for `/present`, `/cleanup`, `/healthz`, and `/metrics`. |
| **Explanation** | [Security Model & Threat Matrix](docs/explanation/security-model.md) | In-depth rationale: separating traffic gateways from credentials gateways. |
| | [Challenge Tracking & Concurrency](docs/explanation/collision-handling.md) | Mathematical tuple tracking and multi-client collision resolution. |

---

## Security

Legate is engineered with defense-in-depth principles:

- **ANSSI BP-028 v2.0 MIE Compliance**: Architecture designed for isolation in restricted management networks.
- **Timing-Attack Resistance**: Authentication uses `crypto/subtle.ConstantTimeCompare` with dummy comparisons to defeat user enumeration.
- **Starvation-Resistant Rate Limiting**: Authentication is validated **before** rate-limiting token consumption, preventing unauthenticated clients from exhausting quotas.
- **Strict Payload Bounds**: Incoming request bodies are capped at **16 KiB** (`http.MaxBytesReader`) to mitigate memory-exhaustion denial of service.
- **Sanitized Observability**: The `/healthz` probe returns only aggregate domain counts (`domains_count`), and `/metrics` excludes usernames from labels.
- **Zero Third-Party Runtime Bloat**: Implemented with the Go standard library, official Prometheus metrics exporter, and standard YAML parser.

---

## Contributing

We welcome contributions! Please review [CONTRIBUTING.md](CONTRIBUTING.md) for development workflows, testing guidelines, and code conventions.

---

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).

Copyright (c) 2026 FirPic
