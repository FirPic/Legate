# Architecture Explanation: Security Model & Threat Matrix

This document details the architectural rationale behind **Legate**, specifically the strict separation between the **traffic gateway** and the **credentials gateway**, and analyzes defense mechanisms against common attack vectors.

---

## The Fundamental Dilemma: DNS-01 Challenges at the Edge

To issue wildcard TLS certificates (`*.example.com`) or certificates for internal private services not reachable from the public Internet, ACME clients must use the **DNS-01 challenge**.

Traditional setups configure reverse proxies (e.g. Traefik, Caddy, NGINX) directly with upstream DNS provider API tokens (such as Cloudflare, IONOS, or Infomaniak API keys):

```text
┌────────────────────────────────────────────────────────┐
│                      DMZ / Edge                        │
│                                                        │
│   ┌─────────────────┐      Direct DNS Provider API     │
│   │     Traefik     │ ───────────────────────────────> │ Cloudflare / IONOS / Infomaniak
│   │  (Holds Token)  │      (Zone.DNS:Edit Token)       │
│   └─────────────────┘                                  │
└────────────────────────────────────────────────────────┘
```

### The Architectural Flaw
Edge reverse proxies reside in DMZ or exposed network zones directly facing public, untrusted traffic. They process complex protocol handshakes, TLS termination, HTTP parsing, and web routing. If a remote code execution (RCE) vulnerability, path traversal bug, or memory corruption occurs in the edge proxy:
- The attacker immediately obtains the **DNS API token**.
- Even if scoped to `Zone.DNS:Edit`, the attacker can overwrite apex `A`/`AAAA` records, redirect MX mail servers, poison SPF/DKIM TXT records, or deploy rogue CNAME subdomains.

---

## The Legate Solution: Separating Traffic Gateway from Credentials Gateway

**Legate** introduces a strict compartmentalization principle:

```text
┌─────────────────────────┐
│       DMZ / Edge        │
│  ┌───────────────────┐  │
│  │   Traefik (DMZ)   │  │
│  │ (No DNS Secrets)  │  │
│  └─────────┬─────────┘  │
└────────────┼────────────┘
             │ HTTP Basic Auth
             │ POST /present, /cleanup
             │ (Strictly confined to _acme-challenge.<zone>)
             v
┌─────────────────────────┐
│     Secured Zone        │
│  ┌───────────────────┐  │
│  │      Legate       │  │
│  │ (Holds DNS Token) │  │
│  └─────────┬─────────┘  │
└────────────┼────────────┘
             │ HTTPS (REST APIs)
             v
┌─────────────────────────┐
│  Cloudflare / IONOS /   │
│       Infomaniak        │
└─────────────────────────┘
```

1. **Traffic Gateway (Traefik in DMZ):** Only holds a local Basic Auth credential and communicates with Legate over an internal firewall-controlled network path.
2. **Credentials Gateway (Legate in Secured Zone):** The only entity holding DNS API credentials. It evaluates every incoming request against strict domain whitelists and enforces that **only** `_acme-challenge.<domain>` TXT records can ever be manipulated.

---

## Threat Matrix & Mitigation Analysis

| Threat Scenario | Impact without Gateway | Mitigation with Legate |
| :--- | :--- | :--- |
| **Edge Proxy Compromise (RCE / Memory Exploit)** | Attacker steals DNS API tokens and modifies critical infrastructure records (A, AAAA, MX, CNAME, SPF). Full domain takeover. | Attacker only discovers a local Basic Auth password. Legate rejects any attempt to modify non-ACME records or records outside the user's RBAC scope. |
| **Zone Escape / Domain Spoofing** | Attacker requests certificates for unauthorized zones (`example.com.attacker.com` or unrelated apex zones). | Strict RFC 1123 parser and fail-closed domain router reject any domain not explicitly declared in Legate's configuration. |
| **CRLF / Null-Byte DNS Injection** | Attacker injects carriage returns, null bytes, or illegal tokens into challenge values. | Challenge values are strictly constrained to standard RFC 8555 base64url characters (`[A-Za-z0-9_-]`). Malformed characters return `400 Bad Request`. |
| **Denial of Service (Memory Exhaustion)** | Attacker sends massive HTTP payloads to exhaust process memory. | `http.MaxBytesReader` strictly terminates HTTP request bodies at **16 KiB** (`16384` bytes) with `413 Request Entity Too Large`. |
| **User Enumeration / Timing Attacks** | Attacker measures microsecond response deltas between valid and non-existent usernames. | `crypto/subtle.ConstantTimeCompare` is executed unconditionally for all authentication attempts, including running a dummy comparison for non-existent users. |
| **Denial of Service via Rate-Limit Starvation** | Unauthenticated attacker spams endpoints to consume rate-limit quotas of legitimate reverse proxies. | Middleware order is strictly inverted: **Authentication occurs BEFORE rate limiting**. Anonymous brute-force attempts cannot starve authenticated clients. |
| **Supply-Chain Dependency Vulnerabilities** | Flaws in external SDKs compromise runtime execution. | Zero external SDKs: Pure Go standard library (`net/http`, `log/slog`, `crypto/subtle`) with only official Prometheus client and standard YAML parser. Built as a non-root static binary (`65534:65534`). |

---

## Alignment with ANSSI BP-028 v2.0 MIE Standards

Legate is aligned with French cybersecurity agency ANSSI recommendations (BP-028 v2.0 MIE level):
- **Principle of Least Privilege:** Edge machines cannot manage global infrastructure state.
- **Fail-Fast Configuration:** Application refuses to start with ambiguous or unvalidated parameters.
- **Auditable Observability:** Structured JSON logs and Prometheus metrics track every challenge creation, deletion, and failure without logging secrets or credentials.
