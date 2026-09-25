# API Reference Specification

`acme-dns-httpreq-proxy` implements the HTTP webhook interface expected by Lego's [`httpreq`](https://go-acme.github.io/lego/dns/httpreq/) provider, as well as operational endpoints for health monitoring and Prometheus metrics.

---

## Endpoint Summary

| Port / Listener | Method | Path | Auth Required | Purpose |
| :--- | :--- | :--- | :---: | :--- |
| `PORT` (8080) | `POST` | `/present` | **Yes (Basic Auth)** | Publish ACME DNS-01 TXT challenge |
| `PORT` (8080) | `POST` | `/cleanup` | **Yes (Basic Auth)** | Remove ACME DNS-01 TXT challenge |
| `ADMIN_PORT` (9090) | `GET` | `/healthz` | No | Liveness and readiness health probe |
| `ADMIN_PORT` (9090) | `GET` | `/metrics` | No | Prometheus telemetry metrics |

All challenge requests accept and return payloads formatted as `application/json`. The server enforces a maximum payload size limit of **16 KiB** (`16384` bytes) on all incoming request bodies.

---

## 1. `GET /healthz` (Admin Port: 9090)

Returns the operational status of the proxy and the current number of in-flight ACME records.

### Request
```http
GET /healthz HTTP/1.1
Host: 127.0.0.1:9090
```

### Response (200 OK)
```json
{
  "status": "ok",
  "allowed_domain": "example.com",
  "tracked_records": 0
}
```

---

## 2. `GET /metrics` (Admin Port: 9090)

Exposes metrics in standard Prometheus exposition text format. Note: Client usernames are intentionally excluded from metric labels to prevent unauthenticated user enumeration.

### Request
```http
GET /metrics HTTP/1.1
Host: 127.0.0.1:9090
```

### Metric Definitions
- `acme_dns_challenges_total{status="success|error"}`: Total number of ACME challenges processed.
- `acme_dns_active_records`: Instantaneous gauge of active challenge records tracked in memory.
- `acme_dns_cloudflare_requests_total{endpoint="zones|dns_records_create|dns_records_delete|dns_records_list", status="success|<http_code>|error"}`: Outgoing Cloudflare API calls.
- `acme_dns_request_duration_seconds{handler="present|cleanup", status="success|error"}`: Histogram of handler latency in seconds.

---

## 3. `POST /present` (Challenge Port: 8080)

Creates an ACME challenge TXT record on Cloudflare.

### Authentication & RBAC
Requires HTTP Basic Authentication (`Authorization: Basic <credentials>`). The authenticated user must have permissions for the requested subdomain as defined in `USERS`.

### Request Payloads

#### Option A: Standard Mode (Default for Lego / Traefik)
```json
{
  "fqdn": "_acme-challenge.sub.example.com.",
  "value": "LHDhK3oGRvkiefQnx7OOczTY5Tic_xZ6HcMOc_gmtoM"
}
```

#### Option B: Raw Mode (Lego `HTTPREQ_MODE=RAW`)
When running in raw mode, Lego sends the domain and key authorization:
```json
{
  "domain": "sub.example.com",
  "token": "token-value",
  "keyAuth": "key-authorization-string"
}
```
*Note: The proxy derives the FQDN (`_acme-challenge.<domain>`) and computes the SHA256 base64url hash of `keyAuth` automatically.*

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

Deletes an ACME challenge TXT record from Cloudflare.

### Authentication & RBAC
Requires HTTP Basic Authentication (`Authorization: Basic <credentials>`).

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

*Note: If the record was already removed or absent in Cloudflare, the endpoint returns `200 OK` idempotently.*

---

## Error Responses & HTTP Status Codes

When an error occurs, the server responds with a JSON payload:

```json
{
  "status": "error",
  "error": "detailed explanation of the failure"
}
```

| HTTP Status | Reason | Cause |
| :--- | :--- | :--- |
| `400 Bad Request` | Malformed Request | Invalid JSON, missing parameters, or control characters in token. |
| `401 Unauthorized` | Missing / Invalid Auth | Missing `Authorization` header, invalid username/password, or malformed Basic Auth string. |
| `403 Forbidden` | Domain Not Authorized / RBAC | The requested FQDN violates the user's `allowed_subdomains` RBAC policy or is outside `ALLOWED_DOMAIN`. |
| `413 Request Entity Too Large` | Payload Exceeded | Request body exceeds 16 KiB limit (`16384` bytes). |
| `429 Too Many Requests` | Rate Limit Exceeded | Client exceeded the allowed requests per minute. Includes `Retry-After: 1` header. |
| `502 Bad Gateway` | Upstream API Error | Cloudflare API rejected the request or network error occurred. Internal details are masked. |
| `500 Internal Error` | Internal Failure | Unexpected internal panic (caught by recovery middleware). |
