# Quickstart: Run acme-dns-httpreq-proxy with Docker

In this 5-minute tutorial, you will launch `acme-dns-httpreq-proxy` using Docker or Podman, verify its health status, publish an ACME challenge TXT record, and clean it up using `curl`.

---

## Prerequisites

Before starting, ensure you have:
1. Docker or Podman installed on your machine.
2. A Cloudflare account managing a DNS zone (e.g., `example.com`).
3. A Cloudflare API Token with `Zone.DNS:Edit` permissions on that zone (see [How-To: Create Scoped Cloudflare Token](../how-to/cloudflare-token.md)).

---

## Step 1: Start the Proxy Container

Run the proxy container using `docker run` (or `podman run`). Replace the environment variables with your actual values:

```bash
docker run -d \
  --name acme-dns-proxy \
  -p 8080:8080 \
  -e CLOUDFLARE_API_TOKEN="your-cf-api-token-here" \
  -e ALLOWED_DOMAIN="example.com" \
  -e USERS="traefik:SuperSecretPassword123" \
  -e LOG_LEVEL="debug" \
  ghcr.io/firpic/acme-dns-httpreq-proxy:latest
```

> **Note:** If you haven't pulled the container yet or are testing a local build, you can build it with `docker build -t ghcr.io/firpic/acme-dns-httpreq-proxy:latest -f Containerfile .`.

---

## Step 2: Check Service Health

The proxy exposes a public, unauthenticated health check endpoint on `/healthz`. Verify the container is running:

```bash
curl -s http://localhost:8080/healthz
```

**Expected output:**
```json
{
  "allowed_domain": "example.com",
  "status": "ok",
  "tracked_records": 0
}
```

The response indicates that the proxy is healthy and no challenge records are currently active.

---

## Step 3: Present an ACME Challenge

Simulate Traefik or Lego sending an ACME DNS-01 challenge to the `/present` endpoint. Basic Authentication is required.

```bash
curl -i -X POST http://localhost:8080/present \
  -u "traefik:SuperSecretPassword123" \
  -H "Content-Type: application/json" \
  -d '{
    "fqdn": "_acme-challenge.test.example.com.",
    "value": "V0RBMXExMlhfTjF2TXE0NzlqS05aV0g2R3V1NmdtVzM="
  }'
```

**Expected output:**
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

Cloudflare now contains the TXT record for `_acme-challenge.test.example.com`.

---

## Step 4: Check Active Records and Metrics

Scrape the Prometheus metrics endpoint to inspect challenge tracking:

```bash
curl -s http://localhost:8080/metrics | grep acme_dns
```

**Expected output:**
```text
# HELP acme_dns_active_records Current count of active ACME DNS TXT challenge records tracked in memory.
# TYPE acme_dns_active_records gauge
acme_dns_active_records 1
# HELP acme_dns_challenges_total Total number of ACME DNS challenges processed, partitioned by status and client.
# TYPE acme_dns_challenges_total counter
acme_dns_challenges_total{client="traefik",status="success"} 1
```

Querying `/healthz` will also show `"tracked_records": 1`.

---

## Step 5: Clean Up the Challenge Record

Once the ACME CA (Let's Encrypt) has validated the DNS record, the client calls `/cleanup`:

```bash
curl -i -X POST http://localhost:8080/cleanup \
  -u "traefik:SuperSecretPassword123" \
  -H "Content-Type: application/json" \
  -d '{
    "fqdn": "_acme-challenge.test.example.com.",
    "value": "V0RBMXExMlhfTjF2TXE0NzlqS05aV0g2R3V1NmdtVzM="
  }'
```

**Expected output:**
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

The record is deleted from Cloudflare, and the in-memory tracker count returns to 0.

---

## Clean Up Tutorial Resources

To stop and remove the container:

```bash
docker stop acme-dns-proxy && docker rm acme-dns-proxy
```

---

## Next Steps

- Integrate Traefik v2 / v3 with the proxy: [Traefik httpreq Guide](../how-to/traefik-httpreq.md).
- Harden the deployment using systemd or rootless Podman: [Hardening Guide](../how-to/systemd-hardening.md).
- Understand the threat model: [Security Model Explanation](../explanation/security-model.md).
