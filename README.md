# Secure Blockchain-Based Platform for IoT Telemetry Integrity and Controlled Sharing

The question we set out to answer is simple to state and surprisingly hard to solve properly: **how do you prove that a sensor reading sitting in a database today is exactly the one the sensor sent weeks ago, and how do you share that data with different people without giving everyone everything?**

Our answer is a full pipeline that runs from simulated low-power IoT motes all the way to a web dashboard, with a Hyperledger Fabric blockchain acting as an independent, tamper-evident witness in the middle.

## The idea in one paragraph

Every sensor reading is encrypted and authenticated on the mote itself, carried over an IPv6/RPL mesh, decrypted and validated at a gateway, then stored in two places at once: the full reading goes into a local SQLite database (off-chain), and a SHA-256 fingerprint of it goes into a Hyperledger Fabric ledger (on-chain). If anyone later edits the database, the fingerprint no longer matches and the record is flagged. On top of that, a second blockchain layer holds access policies and an audit log, so the data owner decides who sees what (full values, hourly aggregates, or hashes only) and every access decision, granted or denied, is permanently recorded.

## Architecture

```
IoT Motes (Contiki-NG / Cooja, AES-CCM-8 on-mote)
    │  UDP over IPv6, three independent RPL DODAGs (one per data type)
    ▼
Gateways (Python, one process per data type)
    │  decrypt + authenticate + replay check, then publish
    ▼
MQTT Broker (Mosquitto, TLS on port 8883)
    │
    ▼
Ingestion Service (Python)
    ├── SQLite          ← full reading (off-chain)
    └── Fabric ledger   ← SHA-256 hash only (on-chain)
    │
    ▼
Flask APIs (JWT)
    ├── Integrity API, port 5000  → integrity dashboard
    └── Sharing API,  port 5001  → role-based data access
    │
    ▼
Web Dashboards (integrity view + access control view)
```

A background **reverifier** continuously re-hashes stored rows and checks them against the ledger, so tampering is detected without anyone having to click a button. The API runs in strict mode: only rows verified as intact are ever served.

## What the platform actually does

**Integrity, end to end.** Each reading is protected in transit by AES-CCM-8 (an authenticated encryption mode, NIST SP 800-38C) computed on the mote itself, and protected at rest by continuous comparison against the immutable on-chain hash. These are two different threats handled at two different layers, and neither mechanism can replace the other.

**Per-device keys, no key distribution headache.** Device keys are derived with HKDF (RFC 5869) from a single master key, so the gateway can reconstruct any device key on the fly and the motes never transmit key material.

**Controlled sharing with on-chain enforcement.** The chaincode stores an access policy per device and per data type. Four roles exist (owner, analytics, auditor, admin) and each one gets a different projection of the same data: full values, hourly aggregates, or hash-only. The decision is made by the chaincode's `CheckAccess` function, not by the API and certainly not by the UI. Per-device and per-type policies are combined with AND logic, so the least permissive rule always wins.

**Fail-closed by design.** A missing policy, an unknown role, or a ledger read error all produce the same answer: denied. We deliberately collapse the failure reasons into one response so an attacker can't use error messages as a probing oracle.

**Everything is audited.** Every access decision, including denials, is appended to an on-chain log with a composite key that allows efficient per-device queries.

## Tech stack

| Layer | Technology |
|---|---|
| Sensor simulation | Contiki-NG + Cooja, MSP430 motes |
| Routing | RPL / 6LoWPAN, three isolated DODAGs |
| On-mote crypto | tinyAES + a custom CCM-8 implementation |
| Key derivation | HKDF-Expand (RFC 5869) |
| Transport | MQTT over TLS (Mosquitto, Paho client) |
| Ledger | Hyperledger Fabric 2.5, Go chaincode (CCaaS), channel `mychannel` |
| Off-chain storage | SQLite in WAL mode |
| APIs | Python Flask + JWT |
| Frontend | Plain HTML/JS dashboards |

## Repository layout

```
iot-pipeline/
├── gateway/        UDP→MQTT bridge, CCM decryption, key_manager.py (HKDF)
├── infra/          Mosquitto config, TLS certificates, docker-compose
├── ingestion/      MQTT→SQLite+Fabric ingestion, fabric client bridge
├── chaincode/      Go smart contract (iot-integrity, v1.2)
├── api/            Integrity API (5000) and Sharing API (5001)
├── dashboard/      index.html (integrity) and sharing.html (access control)
└── db/             SQLite database (created at runtime)
```

## License

Academic project. If you reuse parts of it, a mention is appreciated.
