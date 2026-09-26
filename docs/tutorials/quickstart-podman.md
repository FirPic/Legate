# Quickstart: Run Legate with Podman

In this 5-minute hands-on tutorial, you will launch **Legate** using Podman, verify its operational health status, publish an ACME DNS-01 challenge TXT record, inspect telemetry metrics, and perform cleanup using standard `curl` commands.

---

## Prerequisites

Before starting, ensure you have:
1. Podman installed on your host.
2. An upstream DNS provider account (e.g. Cloudflare, IONOS, or Infomaniak) managing your domain (e.g., `example.com`).
3. An API token with DNS edit permissions on that zone (see [How-To: Create Scoped Cloudflare Token](../how-to/cloudflare-token.md)).

---

## Step 1: Start the Legate Container

Legate strictly enforces RFC 9106 Argon2id password hashing and rejects plaintext passwords in environment variables.

First, generate an Argon2id hash using Legate's built-in `hash-password` subcommand:

# Interactive prompt (masked input, avoids storing password in shell history):
HASH=$(podman run --rm -ti ghcr.io/firpic/legate:latest hash-password)
```

Now, launch the Legate container using `podman run`. Legate exposes two separate ports:
- **`8080` (Challenge Port)**: Authenticated endpoint for reverse proxies (`/present`, `/cleanup`).
- **`9090` (Admin Port)**: Unauthenticated internal endpoint for monitoring (`/healthz`, `/metrics`).

```bash
podman run -d \
  --name legate \
  -p 8080:8080 \
  -p 127.0.0.1:9090:9090 \
  -e CLOUDFLARE_API_TOKEN="your-cf-api-token-here" \
  -e ALLOWED_DOMAIN="example.com" \
  -e USERS="traefik:${HASH}" \
  -e LOG_LEVEL="debug" \
  ghcr.io/firpic/legate:latest
```

> [!TIP]
> To build from source locally using Podman:
> ```bash
> podman build -t ghcr.io/firpic/legate:latest -f Containerfile .
> ```

---

## Step 2: Check Service Health

Legate exposes an unauthenticated health probe on the admin port (`9090`). Verify that the instance is operational:

```bash
curl -s http://127.0.0.1:9090/healthz
```

**Expected JSON response:**
```json
{
  "domains_count": 1,
  "status": "ok",
  "tracked_records": 0
}
```

The response confirms that Legate is running healthy, has 1 domain configured, and has 0 active challenge records in memory.

---

## Step 3: Present an ACME Challenge

Simulate Traefik, Caddy, or Lego sending an ACME DNS-01 challenge to `/present`. HTTP Basic Authentication is required.

```bash
curl -i -X POST http://localhost:8080/present \
  -u "traefik:SuperSecretPassword123" \
  -H "Content-Type: application/json" \
  -d '{
    "fqdn": "_acme-challenge.test.example.com.",
    "value": "V0RBMXExMlhfTjF2TXE0NzlqS05aV0g2R3V1NmdtVzM="
  }'
```

**Expected HTTP response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json
Date: ...
Content-Length: 118

{
  "status": "success",
  "action": "present",
  "fqdn": "_acme-challenge.test.example.com",
  "record_id": "372e67954025e0ba6aaa6d586b9e0b59"
}
```

Upstream DNS now holds the ACME TXT record for `_acme-challenge.test.example.com`.

---

## Step 4: Inspect Metrics & Challenge Tracking

Query the Prometheus telemetry endpoint on admin port `9090`:

```bash
curl -s http://127.0.0.1:9090/metrics | grep acme_dns
```

**Expected output:**
```text
# HELP acme_dns_active_records Current count of active ACME DNS TXT challenge records tracked in memory.
# TYPE acme_dns_active_records gauge
acme_dns_active_records 1
# HELP acme_dns_challenges_total Total number of ACME DNS challenges processed, partitioned by status.
# TYPE acme_dns_challenges_total counter
acme_dns_challenges_total{status="success"} 1
```

Querying `/healthz` will simultaneously display `"tracked_records": 1`.

---

## Step 5: Clean Up the Challenge Record

Once the ACME Certificate Authority (e.g. Let's Encrypt) has validated the DNS record, the reverse proxy issues `/cleanup`:

```bash
curl -i -X POST http://localhost:8080/cleanup \
  -u "traefik:SuperSecretPassword123" \
  -H "Content-Type: application/json" \
  -d '{
    "fqdn": "_acme-challenge.test.example.com.",
    "value": "V0RBMXExMlhfTjF2TXE0NzlqS05aV0g2R3V1NmdtVzM="
  }'
```

**Expected HTTP response:**
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "success",
  "action": "cleanup",
  "fqdn": "_acme-challenge.test.example.com",
  "record_id": "372e67954025e0ba6aaa6d586b9e0b59"
}
```

The TXT record is deleted upstream, and the in-memory tracker count returns to 0.

---

## Teardown

To stop and remove the test container:

```bash
podman stop legate && podman rm legate
```

---

## Next Steps

- Deploy a full production stack with Traefik: [Traefik httpreq Guide](../how-to/traefik-httpreq.md).
- Multi-domain and multi-provider configuration: [Configuration Reference](../reference/configuration.md).
- Security hardening for production: [Systemd & Podman Quadlet Hardening](../how-to/systemd-hardening.md).
- Deep dive into the security architecture: [Security Model Explanation](../explanation/security-model.md).
