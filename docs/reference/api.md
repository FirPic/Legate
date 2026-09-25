# API Reference Specification

`acme-dns-httpreq-proxy` implements the HTTP webhook interface expected by Lego's [`httpreq`](https://go-acme.github.io/lego/dns/httpreq/) provider, as well as operational endpoints for health monitoring and Prometheus metrics.

---

## Endpoint Summary

| Method | Path | Auth Required | Purpose |
| :--- | :--- | :---: | :--- |
| `GET` | `/healthz` | No | Liveness and readiness health probe |
| `GET` | `/metrics` | No | Prometheus telemetry metrics |
| `POST` | `/present` | **Yes (Basic Auth)** | Publish ACME DNS-01 TXT challenge |
| `POST` | `/cleanup` | **Yes (Basic Auth)** | Remove ACME DNS-01 TXT challenge |

All requests accept and return payloads formatted as `application/json` (except `/metrics` which returns Prometheus exposition text format). The server enforces a maximum payload size limit of **64 KiB** on all request bodies.

---

## 1. `GET /healthz`

Returns the operational status of the proxy and the current number of in-flight ACME records.

### Request
```http
GET /healthz HTTP/1.1
Host: proxy.internal:8080
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

## 2. `GET /metrics`

Exposes metrics in standard Prometheus exposition text format.

### Request
```http
GET /metrics HTTP/1.1
Host: proxy.internal:8080
```

### Metric Definitions
- `acme_dns_challenges_total{status="success|error", client="<username>"}`: Total number of challenges processed.
- `acme_dns_active_records`: Instantaneous gauge of active challenge records tracked in memory.
- `acme_dns_cloudflare_requests_total{endpoint="zones|dns_records_create|dns_records_delete|dns_records_list", status="success|<http_code>|error"}`: Outgoing Cloudflare API calls.
- `acme_dns_request_duration_seconds{handler="present|cleanup", status="success|error"}`: Histogram of handler latency in seconds.

---

## 3. `POST /present`

Creates an ACME challenge TXT record on Cloudflare.

### Authentication
Requires HTTP Basic Authentication (`Authorization: Basic <credentials>`). The username must match an entry configured in `USERS`.

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

## 4. `POST /cleanup`

Deletes an ACME challenge TXT record from Cloudflare.

### Authentication
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
| `400 Bad Request` | Malformed Request | Invalid JSON, missing parameters, control characters in token, or payload > 64 KiB. |
| `401 Unauthorized` | Missing / Invalid Auth | Missing `Authorization` header, invalid username/password, or malformed Basic Auth string. |
| `403 Forbidden` | Domain Not Authorized | The requested FQDN does not match `_acme-challenge.<ALLOWED_DOMAIN>` or a subdomain thereof. |
| `502 Bad Gateway` | Upstream API Error | Cloudflare API rejected the request, returned an error code, or network timeout occurred. |
| `500 Internal Error` | Internal Failure | Unexpected internal panic (caught by recovery middleware). |
