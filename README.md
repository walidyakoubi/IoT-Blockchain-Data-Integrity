# PFE Final Overview — IoT Data Integrity & Sharing on Hyperledger Fabric

**Author:** Oualid yakoubi — Master 2, Telecommunication Systems
**Project family:** Secure IoT pipeline + Permissioned blockchain
**Status at close:** Pipeline fully operational, 22 implementation steps completed

---

## 1. Project Identity (Simple Explanation)

In one sentence:

> *A simulated IoT network where sensor readings are end-to-end encrypted, transported through a real protocol stack (RPL → UDP/IPv6 → MQTT/TLS), anchored on a Hyperledger Fabric blockchain for tamper-evident integrity, and exposed to multiple consumer roles through an on-chain access-control policy with a live audit trail.*

Three problems are solved in the same architecture:

| Problem | Layer that solves it | Mechanism |
|---|---|---|
| Can data be **trusted** end-to-end? | Cryptography + Blockchain | AES-CCM-8 (AEAD) + SHA-256 anchoring on Fabric |
| Can tampering be **detected automatically**? | Pipeline | Continuous background reverifier + strict-mode API |
| Can **different consumers** see different views, with audit? | Chaincode | On-chain access policies (per-device + per-type) + access log |

This is the academic value: the project is not a single demo of one idea, but an **end-to-end pipeline** in which each architectural layer earns one defensible security property.

---

## 2. Final Architecture (Engineering View)

```
        ┌────────────────────────────────────────────────────────────────┐
        │                     COOJA SIMULATION (MSP430)                  │
        │                                                                │
        │  3 DODAGs / 3 IPv6 prefixes / 3 Border Routers                 │
        │                                                                │
        │   temp motes  ──► BR_temp  (aaaa::/64)                         │
        │   hum motes   ──► BR_hum   (bbbb::/64)                         │
        │   press motes ──► BR_press (cccc::/64)                         │
        │                                                                │
        │   Firmware: tinyAES + custom CCM-8 (NIST SP 800-38C)           │
        └─────────┬───────────────┬──────────────────┬───────────────────┘
                  │ SLIP/serial   │ SLIP/serial      │ SLIP/serial
                  ▼               ▼                  ▼
              tunslip6        tunslip6           tunslip6
              (tun0)          (tun1)             (tun2)
                  │               │                  │
                  ▼               ▼                  ▼
          ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
          │ gateway_temp │ │ gateway_hum  │ │ gateway_press│   ← Option G1
          │  bind aaaa::1│ │  bind bbbb::1│ │  bind cccc::1│   (3 processes)
          └──────┬───────┘ └──────┬───────┘ └──────┬───────┘
                 │                │                │
                 │  AAD verify → AES-CCM-8 decrypt → seq check
                 │
                 └──────────► Mosquitto (MQTT over TLS, port 8883)
                                          │
                                          ▼
                              ┌───────────────────────┐
                              │  Ingestion service    │
                              │   ├─► SQLite (full)   │
                              │   └─► Fabric (hash)   │
                              └───────────────────────┘
                                          │
              ┌───────────────────────────┼────────────────────────────┐
              ▼                           ▼                            ▼
       Reverifier (60s)        API v1.0 — Integrity            API v1.1 — Sharing
       (background loop)       (port 5000, strict mode)        (port 5001, role-aware)
                                          │                            │
                                          ▼                            ▼
                                Dashboard v1.0                 Dashboard v1.2
                                (intact-only view)             (role-filtered UI)
                                                                       │
                                                                       ▼
                                                          Hyperledger Fabric v1.2
                                                          - StoreHash / VerifyHash
                                                          - RegisterDevice / Policy
                                                          - CheckAccess (AND-compose)
                                                          - LogAccess (audit trail)
```

---

## 3. Chronological Map of What Was Built

The project did not start as 22 steps. The list below is the **honest order of construction**, showing how each step earned an additional defensible property.

### Phase A — Pipeline (Steps 1–9)
| # | Step | Deliverable |
|---|---|---|
| 1 | Fabric network setup | Test-network up, channel `mychannel` |
| 2 | Docker 29.x compatibility | Pre-created `fabric_test` network, TCP socket workaround |
| 3 | Chaincode v1.0 | `StoreHash` / `VerifyHash` / `GetRecord` |
| 4 | CCaaS approach | Chaincode as Docker container (bypasses WSL2 socket bugs) |
| 5 | Deploy & verify | First successful end-to-end anchoring |
| 6 | `fabric_client.py` | Subprocess wrapper around `peer chaincode` CLI |
| 7 | Complete pipeline files | Gateway, ingestion, API, DB schema |
| 8 | Dashboard "Verify" feature | Per-row + Verify-All buttons |
| 9 | API `/verify` endpoint | First user-facing integrity check |

### Phase B — Security Hardening (Steps 10–14)
| # | Step | What it earned |
|---|---|---|
| 10 | Device authentication (HMAC + HKDF) | Per-device keys, message authenticity |
| 11 | Contiki-NG self-contained SHA-256 | Removed external module dependency that broke MSP430 builds |
| 12 | MQTT over TLS (port 8883) | Confidentiality on the gateway↔broker↔ingestion path |
| 13 | Migration HMAC → AES-CCM-8 | **AEAD**: authenticity + confidentiality + AAD in *one* primitive |
| 14 | Continuous background verification | Strict-mode API + reverifier process |

### Phase C — Embedded-Side Engineering (Steps 15–16)
| # | Step | What it earned |
|---|---|---|
| 15 | MSP430 ROM overflow fix | `-Os` + TCP disabled (UDP-checksum optimisation rejected per §26) |
| 16 | Pipeline debugging session | Five external probes, layered failure-mode methodology |

### Phase D — Data Sharing (Steps 17–22)
| # | Step | What it earned |
|---|---|---|
| 17 | Multi-role access control (chaincode v1.1) | Per-device policy, on-chain audit log, four roles |
| 18 | Deployment & lifecycle lessons | `redeploy.sh`, sequence-number discipline |
| 19 | Multi-DODAG RPL architecture | Routing-layer type separation (3 prefixes) |
| 20 | Per-type gateway isolation (Option G1) | Process-level kernel isolation |
| 21 | Per-type chaincode policies (v1.2) | AND-composition, type-level kill switch |
| 22 | Dashboard v1.2 + demo mode | Role-filtered UI, live policy-change demo |

---

## 4. Strong Points (the headline arguments for the jury)

These are the points that will distinguish this PFE in the eyes of the jury. Each one is **defensible by a specific artifact in the codebase**.

### Strong Point 1 — Defense-in-depth across the OSI stack

The project does not rely on a single security mechanism. **Type separation alone is enforced at five independent layers** (after §29/§30):

| Layer | Mechanism |
|---|---|
| Radio | Three Cooja clusters, distinct coordinate regions |
| Routing | Three RPL DODAGs, three IPv6 prefixes |
| Process | Three gateway processes, three socket binds |
| Cryptography | AAD `type=T` authenticated by AES-CCM-8 tag |
| Messaging | Three MQTT topic branches (`iot/readings/{type}/{id}`) |

Any one layer would catch a misrouted packet on its own. This is the difference between a checkbox security project and an architecture.

### Strong Point 2 — Integrity "by construction", not by user action

The API serves **only** rows whose SQLite `verified` column equals `'intact'`. The reverifier process updates that column every 60 seconds against the Fabric ledger. The dashboard cannot, *by structural property*, display tampered data — there is no code path that produces such an output.

This is a structural guarantee, not a runtime check. It eliminates the failure mode of a negligent user not clicking "Verify".

### Strong Point 3 — Fail-closed everywhere

Every authorization path collapses all failure modes into the same response:
- `CheckAccess` returns `"denied"` whether the policy is missing, the role is not whitelisted, the ledger read failed, or the JSON parse failed.
- Gateway CCM verification: any mismatch (tag, AAD type, sequence number) drops the packet silently — no error oracle for the attacker.
- AND-composition of device + type policies (§31): adding either layer can only *tighten* access.

The pattern is the same across the stack, and it is the security-architecture principle that earns the project the right to call itself defense-in-depth.

### Strong Point 4 — Real cryptography on a real constrained device

The mote firmware fits inside MSP430's 48 KB ROM and runs:
- tinyAES (kokke/tiny-AES-c, public domain) — 128-bit AES-ECB primitive
- Custom CCM-8 implementation per NIST SP 800-38C
- Self-contained SHA-256 + HMAC + HKDF for per-device key derivation at boot

The ROM-budget table (§25) is part of the engineering contribution — it shows the tension between security and constrained-device reality, and it documents the choices (`-Os`, TCP disabled) that resolved it without sacrificing protocol conformance (UDP-checksum optimization rejected per RFC 8200, §26).

This is honest IoT-security engineering, not desktop-grade cryptography pretending to be embedded.

### Strong Point 5 — On-chain access control + audit trail in the same trust boundary as integrity

The same Fabric ledger holds:
1. SHA-256 payload hashes (integrity anchoring)
2. `AccessPolicy` assets (who can read what)
3. `AccessLogEntry` records (what was actually granted/denied, with reason)

A regulator auditing the system has **one** source of truth for both "is the data intact?" and "who accessed it under what authorization?". This is rare in IoT systems — most pipelines treat these as two separate problems.

### Strong Point 6 — Honest engineering documentation

The session log includes:
- **Rejected optimizations** (UDP checksum disable — kernel-drop on IPv6) — kept in the memoir as a methodological lesson.
- **Five external probes** for pipeline validation (`tcpdump`, `mosquitto_sub`, `sqlite3 .schema`, `docker ps` + `peer chaincode query`).
- **A six-step recovery procedure** for restarting the whole stack after WSL2/Docker resets.
- **Limitation sections** at the end of every major step (§29.8, §30.7, §31.8) where every honest weakness is named.

The memoir framing of §26 ("Lessons in Layered Pipeline Composition") turns a debugging session into a defensible engineering contribution. A jury that values intellectual honesty over a polished surface will weigh this heavily.

---

## 5. Final Security Property Matrix

| Property | Mechanism | Layer | Status |
|---|---|---|---|
| Data Authenticity (source) | AES-CCM-8 + per-device HKDF key | Mote → GW | ✅ |
| Data Confidentiality (UDP mote link) | AES-CCM-8 ciphertext | Mote → GW | ✅ |
| Replay Protection | Strictly increasing `seq` counter | Application | ✅ |
| Transport Confidentiality (MQTT) | TLS on port 8883 | GW ↔ Broker ↔ Ingest | ✅ |
| Transport Confidentiality (Fabric) | Mutual TLS (native) | Ingest ↔ Peer | ✅ |
| Data Integrity (at rest) | SHA-256 hash anchored on Fabric | Storage | ✅ |
| Continuous Integrity Verification | Reverifier loop (60 s) + strict-mode API | Pipeline | ✅ |
| Default-deny on unverified data | `verified='intact'` filter in API | API | ✅ |
| Multi-consumer access control | On-chain `AccessPolicy` + `CheckAccess` | Chaincode | ✅ |
| Per-type kill switch | `PolicyByType` + AND-composition | Chaincode | ✅ |
| Auditable authorization | `AccessLogEntry` (every decision logged) | Chaincode | ✅ |
| Type separation across stack | Radio / RPL / Process / Crypto / MQTT | 5 layers | ✅ |
| API authentication | JWT tokens (HS256) | Application | ✅ |
| Forward Secrecy | — | — | ❌ (perspective: DTLS + ECDHE) |

The only ❌ remaining is **forward secrecy**, an inherent limitation of pre-shared-key designs on constrained devices. This is documented as a perspective, not hidden.

---

## 6. Honest Limitations

These are the limitations to name plainly in the memoir and the soutenance. Acknowledging them is a strong point, not a weakness.

| Layer | Limitation | Why it remains |
|---|---|---|
| Mote ↔ Gateway | No DTLS, no forward secrecy | MSP430 ROM and energy budget |
| RF | Routing isolation, not RF isolation (all three DODAGs share Cooja's radio medium) | True RF separation needs distinct 802.15.4 channels → 3 different firmwares |
| Authentication (sharing API) | Four hardcoded users with plaintext passwords | Demo-grade; production needs OIDC/LDAP |
| Policy granularity | Sensor class, not data attributes (no "aggregated humidity between 06:00–18:00") | Would require Attribute-Based Access Control (ABAC) |
| Composition rule | Hard-coded to AND/least-permissive | Generalising needs a `composition_mode` config asset |
| Sensor types | Three hardcoded in `validSensorType` switch | A schema-table on chain would be more elegant (future work) |
| Audit log | Synchronous `LogAccess` adds ~500 ms per API call (or async with "lost on crash" window) | Trade-off between latency and audit completeness |
| Single Fabric org | The test-network single-org topology limits the "decentralized" claim | Multi-org would need real CA infrastructure |
| Performance scope | Numbers reported on a single WSL2 host | Not a production benchmark; a "feasibility floor" measurement |

---

## 7. Measured Numbers (for the memoir's results chapter)

| Metric | Measured | Reference / Notes |
|---|---|---|
| MQTT ingestion latency | ~5 ms | Within < 10 ms target |
| Fabric `StoreHash` (invoke) | ~500 ms | Fabric is consensus-bound; expected |
| Fabric `VerifyHash` (query) | ~50 ms | No consensus needed, just read |
| Fabric `CheckAccess` (query) | ~50 ms | Used on every sharing-API call |
| End-to-end access-decision latency | < 200 ms | HTTP parse + JWT + CheckAccess + SQLite read |
| Tamper detection rate | 100 % | Reverifier catches all SQLite-only modifications |
| Tamper detection latency (worst case) | ≤ 60 s | Reverifier loop interval |
| Policy update propagation | ≤ 2 s | Fabric block-cut interval (test-network default) |

These are reported as **feasibility-floor numbers**, not production benchmarks. The methodology section should make that explicit.

---

## 8. Recommended Soutenance Demo (35 minutes)

A demonstration sequence that hits every strong point in order:

**T+0 — Start.** Show the running stack: `docker ps` (Fabric peers, Mosquitto), `ps -ef | grep gateway` (three processes), `ss -unlp | grep 3000` (three bound sockets, three IPv6 addresses).

**T+5 — Live data.** Show the dashboard auto-refreshing every 5 s. Three sensor types appear in three separate panels. *Strong points 1 and 4.*

**T+10 — Integrity-by-construction.** Tamper one SQLite row manually. Show the reverifier log line `STATE CHANGE … intact → tampered`. Show the dashboard re-rendering with `"1 tampered hidden"` banner. **No user clicked anything.** *Strong point 2.*

**T+18 — Access control.** Log in as `bob` (analytics role). Query `/readings/aggregated` — 200, see hourly stats. Log in as `charlie` (auditor). Query the same endpoint — 403. Query `/readings/verify` — 200, see hashes only. *Strong point 5.*

**T+25 — Type-level kill switch.** As admin, `PUT /policy/type/hum` removing `analytics` from readers. Within 2 seconds, bob's previously-successful query returns 403 with reason `"type policy denied"`. Temperature queries still work. *Strong point 1 (chaincode layer) + Strong point 3 (fail-closed).*

**T+30 — Audit trail.** Query `/audit/mote-90` as auditor. Show the on-chain log entry for the just-denied request, including the exact reason and timestamp. *Strong point 5 — single trust boundary for integrity + authorization.*

**T+33 — Honest close.** Show the limitations table from §6. Name forward secrecy and the demo-grade auth as the two main gaps. *Strong point 6.*

**T+35 — Questions.**

---

## 9. Closing Reflection

What this PFE demonstrates is not a novel cryptographic primitive or a new blockchain protocol. It demonstrates something arguably harder and more useful for an engineer's first major project: **the discipline of composing well-understood mechanisms into a system whose security properties are visible and defensible at every layer.**

The project's value to a jury is not "we implemented X". It is:

1. *We placed the trust boundary where the decision is made, not where the data is consumed.*
2. *We made the security properties structural, not procedural — they hold by construction, not by user vigilance.*
3. *We documented every rejected optimization and every honest limitation, so the system's claims are exactly the system's guarantees — no more, no less.*

If the soutenance comes down to one sentence, it is this:

> *"This project does not claim to be more secure than its mechanisms allow. It claims to make those mechanisms compose cleanly, and to make the composition auditable. That is the contribution."*

---

## Thanks

A long pipeline like this is built one failed compile at a time. The fact that it ends with a working end-to-end demo, twenty-two documented steps, and an honest list of limitations is itself a result worth defending.

Good luck with the soutenance.

— End of overview —
