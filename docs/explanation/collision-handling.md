# Architecture Explanation: Challenge Tracking & Concurrency Resolution

This document explains how **Legate** resolves race conditions, concurrent renewals, and state synchronization across multiple ACME clients.

---

## The Challenge: Concurrency in ACME DNS-01

According to RFC 8555 (Automatic Certificate Management Environment), validating domain ownership via DNS-01 requires placing a cryptographically random token inside a DNS `TXT` record named `_acme-challenge.<domain>`.

### The Race Condition in Multi-Client Environments

In modern multi-tier architectures, multiple ACME clients frequently operate simultaneously:
- An edge reverse proxy (`traefik-dmz`) renewing `*.example.com` or `app.example.com`.
- An internal reverse proxy (`traefik-infra` or Caddy) renewing certificates for internal endpoints.
- A cluster with multiple ingress controllers running parallel renewals.

Because DNS allows **multiple TXT records with the identical name**, both clients can publish their own challenge token simultaneously:

```text
_acme-challenge.example.com. IN TXT "Token-Alpha-From-Client-1"  (DNS Record ID: 101)
_acme-challenge.example.com. IN TXT "Token-Beta-From-Client-2"   (DNS Record ID: 102)
```

### The Naive Gateway Flaw
A naive gateway that deletes records simply by record name (`DELETE WHERE name = '_acme-challenge.example.com'`) creates a severe race condition:
1. Client 1 publishes Token Alpha (Record 101).
2. Client 2 publishes Token Beta (Record 102).
3. Let's Encrypt validates Token Alpha for Client 1.
4. Client 1 calls `/cleanup` for `_acme-challenge.example.com`.
5. The naive gateway deletes **all** TXT records for `_acme-challenge.example.com`.
6. Client 2's validation fails with `NXDOMAIN` / `Record Not Found` because its challenge record was prematurely destroyed.

---

## The Solution: Tuple Tracking `(FQDN, Value) -> Record ID`

Legate eliminates this race condition by tracking the lifecycle of each challenge using a compound tuple:

$$\text{Key} = \text{NormalizedFQDN} \mathbin{\Vert} \text{ChallengeValue} \longrightarrow \text{ProviderRecordID}$$

```text
┌────────────────────────────────────────────────────────┐
│             Internal In-Memory Tracker                 │
│                                                        │
│  _acme-challenge.example.com | Token-Alpha -> rec-101  │
│  _acme-challenge.example.com | Token-Beta  -> rec-102  │
└────────────────────────────────────────────────────────┘
```

### Execution Flow:

1. **Client 1 Calls `/present`:**
   - Body: `{"fqdn": "_acme-challenge.example.com", "value": "Token-Alpha"}`.
   - Legate calls Upstream DNS API: creates TXT record, provider returns `id: "rec-101"`.
   - Tracker saves: `_acme-challenge.example.com|Token-Alpha` = `"rec-101"`.
   - Legate responds with `{"status":"success", "record_id":"rec-101"}`.

2. **Client 2 Calls `/present` Concurrently:**
   - Body: `{"fqdn": "_acme-challenge.example.com", "value": "Token-Beta"}`.
   - Legate calls Upstream DNS API: creates second TXT record, provider returns `id: "rec-102"`.
   - Tracker saves: `_acme-challenge.example.com|Token-Beta` = `"rec-102"`.
   - Legate responds with `{"status":"success", "record_id":"rec-102"}`.

3. **Client 1 Calls `/cleanup`:**
   - Body: `{"fqdn": "_acme-challenge.example.com", "value": "Token-Alpha"}`.
   - Tracker looks up `_acme-challenge.example.com|Token-Alpha` and finds `"rec-101"`.
   - Legate calls Upstream DNS API to delete strictly `rec-101`.
   - Record `rec-101` is deleted. **Record `rec-102` remains completely untouched.**
   - Client 2's validation completes successfully without disruption.

---

## Crash and Restart Resilience: The Fallback Query

What happens if Legate restarts or crashes while an ACME challenge is in flight?

Because Legate is stateless and compute-ephemeral, the in-memory map starts empty after a restart. If Client 1 subsequently sends a `/cleanup` request:

```text
                          ┌───────────────────────────┐
                          │   Incoming POST /cleanup  │
                          └─────────────┬─────────────┘
                                        │
                                        v
                          ┌───────────────────────────┐
                          │   Lookup (FQDN, Value)    │
                          │   in Local Tracker        │
                          └─────────────┬─────────────┘
                                        │
                         Found? ────────┴──────── Not Found?
                            │                          │
                            v                          v
             ┌─────────────────────────┐ ┌─────────────────────────┐
             │ Delete by Record ID     │ │ Fallback Query to       │
             │ directly on Provider    │ │ DNS Provider API        │
             └─────────────────────────┘ │ by Name + Content       │
                                         └─────────────┬───────────┘
                                                       │
                                                       v
                                         ┌─────────────────────────┐
                                         │ Delete Matched Record   │
                                         └─────────────────────────┘
```

1. Legate queries its in-memory tracker.
2. If the tuple is absent (cache miss due to restart), it triggers a **fallback query** to the upstream provider's DNS records listing API filtered by record name (`_acme-challenge.<domain>`) and exact TXT content (`value`).
3. If found upstream, Legate deletes the matching record ID.
4. If not found upstream (already deleted or expired), Legate returns `200 OK` idempotently without error.
