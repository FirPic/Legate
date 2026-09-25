# How-To: Configure Traefik to use Legate

This guide details how to configure **Traefik** (v2 or v3) to delegate ACME DNS-01 challenges to **Legate** using Lego's built-in `httpreq` DNS provider.

---

## Architecture Overview

```text
┌─────────────────────────┐       HTTP Basic Auth         ┌─────────────────────────┐
│     Traefik Edge        │ ────────────────────────────> │        Legate           │
│     (DMZ / Ingress)     │   POST /present, /cleanup     │  (Restricted Sec Zone)  │
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

Traefik does not hold any DNS API credentials. It interacts strictly with Legate through authenticated HTTP requests restricted to its allowed zone or subdomain scope.

---

## 1. Traefik Static Configuration (`traefik.yaml`)

Add a certificate resolver configured for `dnsChallenge` with provider `httpreq`:

```yaml
certificatesResolvers:
  legateResolver:
    acme:
      email: admin@example.com
      storage: /etc/traefik/acme/acme.json
      dnsChallenge:
        provider: httpreq
        delayBeforeCheck: 10 # Wait 10 seconds for authoritative DNS propagation
        resolvers:
          - "1.1.1.1:53"
          - "8.8.8.8:53"
```

---

## 2. Traefik Environment Variables

Traefik reads the configuration for the `httpreq` provider from standard Lego environment variables:

| Variable | Description | Example |
| :--- | :--- | :--- |
| `HTTPREQ_ENDPOINT` | Base URL of the Legate service (challenge port) | `http://legate:8080` |
| `HTTPREQ_USERNAME` | Basic Auth username defined in Legate `users` | `traefik_dmz` |
| `HTTPREQ_PASSWORD` | Basic Auth password defined in Legate `users` | `SuperSecretPassword123` |
| `HTTPREQ_HTTP_TIMEOUT` | Timeout in seconds for HTTP requests to Legate | `30` |

---

## 3. Production Deployment with Podman Compose

Here is a turnkey, multi-network `compose.yaml` isolating Traefik in an ingress network and Legate in an internal backend network:

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
      - "127.0.0.1:9090:9090" # Admin & metrics exposed only on host localhost
    volumes:
      - ./legate.yaml:/etc/legate/config.yaml:ro
      - ./secrets/cf_token:/run/secrets/cf_token:ro
    environment:
      - CONFIG_FILE=/etc/legate/config.yaml

networks:
  edge-network:
    driver: bridge
  security-zone:
    internal: true # No direct ingress from outside
```

> [!NOTE]
> Traefik transmits the plaintext password via `HTTPREQ_PASSWORD` in standard HTTP Basic Authentication over the isolated internal network.
> Legate validates this against the Argon2id hash stored in `legate.yaml` (`password_hash`) or in a secret file (`password_hash_file`). Legate never stores the plaintext password.

Launch the stack using Podman:

```bash
podman compose up -d
```

---

## 4. Configuring Ingress Routers for Certificates

Request wildcard or subdomain certificates using Traefik router labels:

```yaml
services:
  whoami:
    image: traefik/whoami
    networks:
      - edge-network
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.whoami.rule=Host(`service.example.com`)"
      - "traefik.http.routers.whoami.entrypoints=websecure"
      - "traefik.http.routers.whoami.tls=true"
      - "traefik.http.routers.whoami.tls.certresolver=legateResolver"
      - "traefik.http.routers.whoami.tls.domains[0].main=example.com"
      - "traefik.http.routers.whoami.tls.domains[0].sans=*.example.com"
```

---

## 5. Verification & Troubleshooting

1. **Check Traefik Logs:**
   Ensure log level is set to `DEBUG` in Traefik while testing:
   ```text
   DBG ... [acme] [example.com] acme: Cleaning challenge
   DBG ... [acme] Legolog: [INFO] [example.com] acme: Checking DNS record using [1.1.1.1:53 8.8.8.8:53]
   ```

2. **Check Legate Logs:**
   Legate outputs structured JSON logs:
   ```json
   {"time":"2026-09-25T15:30:00Z","level":"INFO","msg":"successfully presented ACME DNS challenge","user":"traefik_dmz","fqdn":"_acme-challenge.example.com","record_id":"372e67954025e0ba6aaa6d586b9e0b59"}
   ```

3. **Common Status Codes:**
   - `401 Unauthorized`: Credentials mismatch. Check `HTTPREQ_USERNAME` and `HTTPREQ_PASSWORD`.
   - `403 Forbidden`: Subdomain rejected by RBAC policy (`allowed_subdomains`) or domain not declared in Legate.
   - `429 Too Many Requests`: Client exceeded the configured `rate_limit_per_minute`.
   - `502 Bad Gateway`: Upstream DNS provider error (e.g. invalid DNS API token or insufficient permissions).
