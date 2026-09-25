# API Reference Specification

**Legate** implements the standard HTTP webhook specification expected by Lego's [`httpreq`](https://go-acme.github.io/lego/dns/httpreq/) provider (used by **Traefik**, **Caddy**, and **Lego** CLI), along with dedicated operational endpoints for health monitoring and Prometheus metrics.

---

## Endpoint Summary

| Port / Listener | Method | Path | Auth Required | Purpose |
| :--- | :--- | :--- | :---: | :--- |
| `PORT` (8080) | `POST` | `/present` | **Yes (Basic Auth)** | Publish ACME DNS-01 TXT challenge |
| `PORT` (8080) | `POST` | `/cleanup` | **Yes (Basic Auth)** | Remove ACME DNS-01 TXT challenge |
| `ADMIN_PORT` (9090) | `GET` | `/healthz` | No | Liveness and readiness health probe |
| `ADMIN_PORT` (9090) | `GET` | `/metrics` | No | Prometheus telemetry metrics |

All challenge endpoints accept and return payloads formatted as `application/json`. The server enforces a maximum payload size limit of **16 KiB** (`16384` bytes) on all incoming request bodies.

---

## 1. `GET /healthz` (Admin Port: 9090)

Returns the operational status of the service, the count of active domain mappings, and the current number of in-flight ACME records.

> [!NOTE]
> In accordance with security hardening practices, domain names are never exposed in `/healthz` to prevent unauthenticated zone enumeration.

### Request
```http
GET /healthz HTTP/1.1
Host: 127.0.0.1:9090
```

### Response (200 OK)
```json
{
  "domains_count": 1,
  "status": "ok",
  "tracked_records": 0
}
```

---

## 2. `GET /metrics` (Admin Port: 9090)

Exposes metrics in standard Prometheus exposition text format. Note: Client usernames are intentionally excluded from metric labels to prevent unauthenticated account enumeration.

### Request
```http
GET /metrics HTTP/1.1
Host: 127.0.0.1:9090
```

### Metric Definitions
- `acme_dns_challenges_total{status="success|error"}`: Total number of ACME challenges processed.
- `acme_dns_active_records`: Instantaneous gauge of active challenge records currently tracked in memory.
- `acme_dns_provider_requests_total{provider="cloudflare|ionos|infomaniak", status="success|<http_code>|error"}`: Outgoing upstream DNS API calls.
- `acme_dns_request_duration_seconds{handler="present|cleanup", status="success|error"}`: Histogram of handler latency in seconds.

---

## 3. `POST /present` (Challenge Port: 8080)

Creates an ACME challenge TXT record on the upstream DNS provider.

### Authentication & RBAC
Requires HTTP Basic Authentication (`Authorization: Basic <base64-credentials>`). The authenticated user must have permissions for the requested subdomain according to their RBAC policy (`allowed_subdomains`).

### Request Payloads

#### Option A: Standard Mode (Default for Lego & Traefik)
```json
{
  "fqdn": "_acme-challenge.sub.example.com.",
  "value": "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM"
}
```

#### Option B: Raw Mode (Lego `HTTPREQ_MODE=RAW`)
When running in raw mode, Lego sends the domain, token, and key authorization string:
```json
{
  "domain": "sub.example.com",
  "token": "token-value",
  "keyAuth": "key-authorization-string"
}
```
*Note: Legate derives the FQDN (`_acme-challenge.<domain>`) and computes the SHA256 base64url hash of `keyAuth` automatically.*

### Response (200 OK)
```json
{
  "status": "success",
  "action": "present",
  "fqdn": "_acme-challenge.sub.example.com",
  "record_id": "372e67954025e0ba6aaa6d586b9e0b59"
}
```

---

## 4. `POST /cleanup` (Challenge Port: 8080)

Deletes an ACME challenge TXT record from the upstream DNS provider.

### Authentication & RBAC
Requires HTTP Basic Authentication (`Authorization: Basic <base64-credentials>`).

### Request Payload
Matches the payload sent during `/present`:
```json
{
  "fqdn": "_acme-challenge.sub.example.com.",
  "value": "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM"
}
```

### Response (200 OK)
```json
{
  "status": "success",
  "action": "cleanup",
  "fqdn": "_acme-challenge.sub.example.com",
  "record_id": "372e67954025e0ba6aaa6d586b9e0b59"
}
```

*Note: If the record was already removed or absent upstream, Legate returns `200 OK` idempotently.*

---

## Error Responses & HTTP Status Codes

When an error occurs, Legate responds with structured JSON:

```json
{
  "status": "error",
  "error": "detailed explanation of the failure"
}
```

| HTTP Status | Reason | Cause |
| :--- | :--- | :--- |
| `400 Bad Request` | Malformed Request | Invalid JSON, non-base64url characters in challenge value, or illegal domain formatting. |
| `401 Unauthorized` | Missing / Invalid Auth | Missing `Authorization` header, invalid username/password, or malformed credentials. |
| `403 Forbidden` | Domain Not Authorized / RBAC | The requested FQDN violates the user's `allowed_subdomains` RBAC policy or belongs to an unconfigured domain. |
| `413 Request Entity Too Large` | Payload Exceeded | Request body exceeds the 16 KiB limit (`16384` bytes). |
| `429 Too Many Requests` | Rate Limit Exceeded | Client exceeded the allowed requests per minute quota. Includes `Retry-After: 1` header. |
| `502 Bad Gateway` | Upstream API Error | Upstream DNS provider rejected the API call or network error occurred. Internal secrets remain masked. |
| `500 Internal Error` | Internal Failure | Unexpected internal panic (intercepted by recovery middleware). |
