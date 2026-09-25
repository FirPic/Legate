# How-To: Configure Traefik to use acme-dns-httpreq-proxy

This guide details how to configure Traefik (v2 or v3) to delegate ACME DNS-01 challenges to `acme-dns-httpreq-proxy` using Lego's built-in `httpreq` DNS provider.

---

## Architecture Overview

```text
┌─────────────────┐       HTTP Basic Auth         ┌─────────────────────────┐
│     Traefik     │ ────────────────────────────> │ acme-dns-httpreq-proxy  │
│  (DMZ / Edge)   │   POST /present, /cleanup     │  (Restricted Sec Zone)  │
└─────────────────┘                               └─────────────────────────┘
                                                               │  Cloudflare API
                                                               │  (Bearer Token)
                                                               v
                                                  ┌─────────────────────────┐
                                                  │   Cloudflare DNS v4     │
                                                  └─────────────────────────┘
```

Traefik does not hold any Cloudflare API credentials. It interacts strictly with `acme-dns-httpreq-proxy` through authenticated HTTP requests restricted to its allowed zone.

---

## 1. Traefik Static Configuration (`traefik.yaml`)

Add a certificate resolver configured for `dnsChallenge` with provider `httpreq`:

```yaml
certificatesResolvers:
  cloudflare:
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
| `HTTPREQ_ENDPOINT` | Base URL of the proxy service | `http://10.53.20.15:8080` |
| `HTTPREQ_USERNAME` | Basic Auth username defined in proxy `USERS` | `traefik_dmz` |
| `HTTPREQ_PASSWORD` | Basic Auth password defined in proxy `USERS` | `SecretPassword123` |
| `HTTPREQ_HTTP_TIMEOUT` | Timeout in seconds for HTTP requests to proxy | `30` |

---

## 3. Deployment Examples

### Option A: Systemd Service (Native VM / Bare-Metal)

In Traefik's systemd drop-in or environment file (e.g. `/etc/traefik/traefik.env` with `chmod 600`):

```ini
# /etc/traefik/traefik.env
HTTPREQ_ENDPOINT=http://10.53.20.15:8080
HTTPREQ_USERNAME=traefik_dmz
HTTPREQ_PASSWORD=SecretPassword123
HTTPREQ_HTTP_TIMEOUT=30
```

In the systemd unit (`/etc/systemd/system/traefik.service`):

```ini
[Unit]
Description=Traefik Edge Reverse Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=traefik
Group=traefik
EnvironmentFile=/etc/traefik/traefik.env
ExecStart=/usr/local/bin/traefik --configfile=/etc/traefik/traefik.yaml
Restart=on-failure
RestartSec=5s

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### Option B: Docker Compose

```yaml
services:
  traefik:
    image: traefik:v3.1
    container_name: traefik
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    environment:
      - HTTPREQ_ENDPOINT=http://acme-dns-proxy:8080
      - HTTPREQ_USERNAME=traefik_dmz
      - HTTPREQ_PASSWORD=SecretPassword123
      - HTTPREQ_HTTP_TIMEOUT=30
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik.yaml:/etc/traefik/traefik.yaml:ro
      - ./acme.json:/etc/traefik/acme/acme.json
```

---

## 4. Configuring Ingress / Routers for Certificates

Request wildcard or subdomain certificates using Traefik router labels:

### Docker Labels Example
```yaml
services:
  whoami:
    image: traefik/whoami
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.whoami.rule=Host(`service.example.com`)"
      - "traefik.http.routers.whoami.entrypoints=websecure"
      - "traefik.http.routers.whoami.tls=true"
      - "traefik.http.routers.whoami.tls.certresolver=cloudflare"
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

2. **Check Proxy Logs:**
   The proxy logs structured JSON messages:
   ```json
   {"time":"2026-09-25T15:30:00Z","level":"INFO","msg":"successfully presented ACME DNS challenge","user":"traefik_dmz","fqdn":"_acme-challenge.example.com","record_id":"372e67954025e0ba6aaa6d586b9e0b59"}
   ```

3. **Common Errors:**
   - `401 Unauthorized`: Check that `HTTPREQ_USERNAME` and `HTTPREQ_PASSWORD` match one of the entries in `USERS`.
   - `403 Forbidden`: Traefik attempted to present a domain that does not end with `ALLOWED_DOMAIN`.
   - `502 Bad Gateway`: Verify that the Cloudflare token has write access to the specific DNS zone.
