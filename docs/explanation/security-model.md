# Architecture Explanation: Security Model & Threat Matrix

This document details the architectural rationale behind `acme-dns-httpreq-proxy`, specifically the separation between the **traffic gateway** and the **credentials gateway**, and analyzes defense mechanisms against common attack vectors.

---

## The Fundamental Dilemma: DNS-01 Challenges at the Edge

To issue wildcard TLS certificates (`*.example.com`) or certificates for internal private services not reachable from the public Internet, ACME clients must use the **DNS-01 challenge**.

Traditional setups configure reverse proxies (e.g., Traefik, Caddy, NGINX) directly with provider API tokens (such as Cloudflare API tokens):

```text
┌────────────────────────────────────────────────────────┐
│                      DMZ / Edge                        │
│                                                        │
│   ┌─────────────────┐      Direct Cloudflare API       │
│   │     Traefik     │ ───────────────────────────────> │ Cloudflare API
│   │  (Holds Token)  │      (Zone.DNS:Edit Token)       │
│   └─────────────────┘                                  │
└────────────────────────────────────────────────────────┘
```

### The Architectural Flaw
Edge reverse proxies reside in DMZ or exposed network zones directly facing public, untrusted traffic. They process complex protocol handshakes, TLS termination, HTTP parsing, and web routing. If a remote code execution (RCE) vulnerability, path traversal bug, or memory corruption occurs in the edge proxy:
- The attacker immediately obtains the **Cloudflare API token**.
- Even if scoped to `Zone.DNS:Edit`, the attacker can overwrite apex `A`/`AAAA` records, redirect MX mail servers, poison SPF/DKIM TXT records, or deploy rogue CNAME subdomains.

---

## The Aegis Solution: Separating Traffic Gateway from Credentials Gateway

`acme-dns-httpreq-proxy` introduces a strict compartmentalization principle:

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
│  │  acme-dns-proxy   │  │
│  │ (Holds CF Token)  │  │
│  └─────────┬─────────┘  │
└────────────┼────────────┘
             │ HTTPS (REST API v4)
             v
┌─────────────────────────┐
│    Cloudflare API       │
└─────────────────────────┘
```

1. **Traffic Gateway (Traefik in DMZ):** Only holds a local Basic Auth credential and talks to the proxy endpoint over an internal firewall-controlled network path.
2. **Credentials Gateway (`acme-dns-httpreq-proxy` in Secured Zone):** The only entity holding the Cloudflare API token. It evaluates every incoming request against a strict domain whitelist and enforces that **only** `_acme-challenge.<ALLOWED_DOMAIN>` TXT records can ever be manipulated.

---

## Threat Matrix & Mitigation Analysis

| Threat Scenario | Impact without Proxy | Mitigation with `acme-dns-httpreq-proxy` |
| :--- | :--- | :--- |
| **Traefik DMZ Compromise (RCE / Memory Exploit)** | Attacker steals Cloudflare API token and modifies all DNS records in the zone (A, AAAA, MX, CNAME). Full domain takeover. | Attacker only discovers a local Basic Auth password. The proxy rejects any attempt to modify non-ACME records or records outside `ALLOWED_DOMAIN`. |
| **Zone Escape / Typosquatting Injection** | Attacker requests certificates for `example.com.attacker.com` or rogue zones. | Strict RFC 1123 parser and prefix/suffix verification ensure that only valid subdomains of `ALLOWED_DOMAIN` are permitted. |
| **CRLF / Null-Byte DNS Injection** | Attacker injects carriage return or null bytes into challenge values to poison DNS servers or escape input sanitizers. | `ValidateChallengeValue` forbids all ASCII control characters (`< 32` or `127`) and enforces length bounds. |
| **Denial of Service (Memory Exhaustion)** | Attacker sends gigabyte-sized JSON payloads to exhaust proxy memory. | `challenge.LimitReader` strictly cuts off HTTP request bodies at **64 KiB**. |
| **User Enumeration / Timing Attack** | Attacker probes proxy with different usernames and measures microsecond response deltas to infer valid accounts. | `crypto/subtle.ConstantTimeCompare` performs constant-time password checks and executes a dummy constant-time comparison when usernames are missing. |
| **Supply-Chain Dependency Vulnerabilities** | Vulnerability in third-party Go libraries compromises the container runtime. | The proxy uses standard library components (`net/http`, `log/slog`, `crypto/subtle`, `sync`) with zero third-party dependencies beyond the official Prometheus metrics client. Built as a minimal non-root static container. |

---

## Alignment with ANSSI BP-028 v2.0 MIE Standards

The implementation is aligned with French cybersecurity agency ANSSI recommendations (BP-028 v2.0 MIE level):
- **Principle of Least Privilege:** Edge machines cannot manage global infrastructure state.
- **Fail-Fast Configuration:** Application refuses to start with ambiguous or unvalidated parameters.
- **Auditable Observability:** Structured JSON logs and Prometheus metrics track every challenge creation, deletion, and failure without logging secrets or credentials.
