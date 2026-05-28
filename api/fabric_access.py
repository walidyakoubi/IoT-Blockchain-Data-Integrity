"""
fabric_access.py — Python wrapper for IoT Data Sharing chaincode (v1.2)
========================================================================
A thin subprocess wrapper around `peer chaincode invoke|query`, mirroring
the existing fabric_client.py pattern. Each exported function corresponds
to one chaincode function.

v1.2 additions vs v1.1:
  • register_device(...)         — now takes a sensor_type parameter
  • register_type_policy(...)    — NEW: per-type policy registration
  • get_type_policy(...)         — NEW
  • update_type_policy(...)      — NEW

Synchronous vs asynchronous LogAccess:
  • log_access(...)             ~500 ms (full Endorse→Order→Commit)
  • log_access_async(...)         fire-and-forget daemon thread
The async variant trades a "lost-on-crash" window for sub-100 ms API
latency. Document this trade-off in the memoir.

Demo-grade (out of scope for production):
  • Subprocess + JSON args is not the production-grade Fabric SDK pattern;
    real systems use fabric-gateway or fabric-sdk-py. Subprocess is chosen
    here for its zero-config compatibility with the CCaaS lifecycle.
  • Org/MSP credentials are loaded from environment variables matching the
    Fabric test-network defaults.

Author: PFE — Telecommunication Systems, USTHB
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

log = logging.getLogger("fabric_access")

# ──────────────────────────────────────────────────────────────────────────────
# Fabric peer environment (matches fabric-samples/test-network defaults)
# ──────────────────────────────────────────────────────────────────────────────

FABRIC_SAMPLES = Path(os.environ.get(
    "FABRIC_SAMPLES_DIR",
    str(Path.home() / "hyperFabric" / "fabric-samples"),
))
TEST_NETWORK = FABRIC_SAMPLES / "test-network"

CHANNEL_NAME = os.environ.get("FABRIC_CHANNEL", "mychannel")
CHAINCODE_NAME = os.environ.get("FABRIC_CHAINCODE", "iot-integrity")

PEER_BIN = os.environ.get(
    "PEER_BIN",
    str(FABRIC_SAMPLES / "bin" / "peer"),
)
ORDERER_ADDR = os.environ.get("ORDERER_ADDR", "localhost:7050")
ORDERER_CA = str(TEST_NETWORK / "organizations" / "ordererOrganizations" /
                 "example.com" / "orderers" / "orderer.example.com" / "msp" /
                 "tlscacerts" / "tlsca.example.com-cert.pem")


def _peer_env() -> dict:
    """Build the environment variables a `peer chaincode` call needs."""
    org1_path = (TEST_NETWORK / "organizations" / "peerOrganizations" /
                 "org1.example.com")
    env = os.environ.copy()
    env.update({
        "FABRIC_CFG_PATH": str(FABRIC_SAMPLES / "config"),
        "CORE_PEER_TLS_ENABLED": "true",
        "CORE_PEER_LOCALMSPID": "Org1MSP",
        "CORE_PEER_TLS_ROOTCERT_FILE": str(
            org1_path / "peers" / "peer0.org1.example.com" / "tls" / "ca.crt"),
        "CORE_PEER_MSPCONFIGPATH": str(
            org1_path / "users" / "Admin@org1.example.com" / "msp"),
        "CORE_PEER_ADDRESS": "localhost:7051",
    })
    return env


# ──────────────────────────────────────────────────────────────────────────────
# Generic invoke/query subprocess wrappers
# ──────────────────────────────────────────────────────────────────────────────

def _invoke(args_json: str, timeout: int = 30) -> bool:
    """
    Execute a `peer chaincode invoke` (write transaction). Returns True on
    success, False on any error. Logs the stderr output for diagnosis.
    """
    cmd = [
        PEER_BIN, "chaincode", "invoke",
        "-o", ORDERER_ADDR,
        "--ordererTLSHostnameOverride", "orderer.example.com",
        "--tls",
        "--cafile", ORDERER_CA,
        "-C", CHANNEL_NAME,
        "-n", CHAINCODE_NAME,
        "--peerAddresses", "localhost:7051",
        "--tlsRootCertFiles", _peer_env()["CORE_PEER_TLS_ROOTCERT_FILE"],
        "--peerAddresses", "localhost:9051",
        "--tlsRootCertFiles", str(
            TEST_NETWORK / "organizations" / "peerOrganizations" /
            "org2.example.com" / "peers" / "peer0.org2.example.com" /
            "tls" / "ca.crt"),
        "--waitForEvent",          # ← ADD THIS LINE
        "-c", args_json,
    ]
    try:
        result = subprocess.run(
            cmd, env=_peer_env(),
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        log.error("invoke timed out after %ds: %s", timeout, args_json[:120])
        return False
    if result.returncode != 0:
        log.error("invoke failed (%d): %s", result.returncode,
                  result.stderr.strip()[:400])
        return False
    log.debug("invoke OK: %s", args_json[:120])
    return True


def _query(args_json: str, timeout: int = 10) -> Optional[str]:
    """
    Execute a `peer chaincode query` (read-only). Returns the raw stdout
    payload (typically JSON) on success, None on any error.
    """
    cmd = [
        PEER_BIN, "chaincode", "query",
        "-C", CHANNEL_NAME,
        "-n", CHAINCODE_NAME,
        "-c", args_json,
    ]
    try:
        result = subprocess.run(
            cmd, env=_peer_env(),
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        log.error("query timed out after %ds: %s", timeout, args_json[:120])
        return None
    if result.returncode != 0:
        # Many queries return rc!=0 for "not found" — log at debug level
        log.debug("query non-zero (%d): %s", result.returncode,
                  result.stderr.strip()[:200])
        return None
    return result.stdout.strip()


# ──────────────────────────────────────────────────────────────────────────────
# v1.0 — Integrity functions (used by reverifier, dashboard)
# ──────────────────────────────────────────────────────────────────────────────

def verify_hash(record_id: str, candidate_hash: str) -> bool:
    args = json.dumps({
        "function": "VerifyHash",
        "Args": [record_id, candidate_hash],
    })
    out = _query(args)
    if out is None:
        return False
    return out.lower() == "true"


def get_record(record_id: str) -> Optional[dict]:
    args = json.dumps({"function": "GetRecord", "Args": [record_id]})
    out = _query(args)
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


# ──────────────────────────────────────────────────────────────────────────────
# v1.1/v1.2 — Per-device access policy
# ──────────────────────────────────────────────────────────────────────────────

def register_device(
    device_id: str,
    owner_org: str,
    sensor_type: str,
    readers: list[str],
    visibility: dict[str, str],
) -> bool:
    """
    Register a device + initial access policy on chain.

    v1.2 NOTE: sensor_type is required (use "" for legacy/unknown).
    Valid values: "temp", "hum", "press", "".
    """
    args = json.dumps({
        "function": "RegisterDevice",
        "Args": [
            device_id, owner_org, sensor_type,
            json.dumps(readers), json.dumps(visibility),
        ],
    })
    return _invoke(args)


def get_policy(device_id: str) -> Optional[dict]:
    args = json.dumps({"function": "GetPolicy", "Args": [device_id]})
    out = _query(args)
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def update_policy(
    device_id: str,
    readers: list[str],
    visibility: dict[str, str],
) -> bool:
    args = json.dumps({
        "function": "UpdatePolicy",
        "Args": [
            device_id, json.dumps(readers), json.dumps(visibility),
        ],
    })
    return _invoke(args)


# ──────────────────────────────────────────────────────────────────────────────
# v1.2 NEW — Per-type access policy
# ──────────────────────────────────────────────────────────────────────────────

def register_type_policy(
    sensor_type: str,
    owner_org: str,
    readers: list[str],
    visibility: dict[str, str],
) -> bool:
    """Register a NEW per-type policy. Fails if one already exists."""
    args = json.dumps({
        "function": "RegisterTypePolicy",
        "Args": [
            sensor_type, owner_org,
            json.dumps(readers), json.dumps(visibility),
        ],
    })
    return _invoke(args)


def get_type_policy(sensor_type: str) -> Optional[dict]:
    """Return the per-type policy, or None if no policy exists for that type."""
    args = json.dumps({"function": "GetTypePolicy", "Args": [sensor_type]})
    out = _query(args)
    if not out or out == "null":
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def update_type_policy(
    sensor_type: str,
    readers: list[str],
    visibility: dict[str, str],
) -> bool:
    """Replace readers and visibility of an existing per-type policy."""
    args = json.dumps({
        "function": "UpdateTypePolicy",
        "Args": [
            sensor_type, json.dumps(readers), json.dumps(visibility),
        ],
    })
    return _invoke(args)


# ──────────────────────────────────────────────────────────────────────────────
# Access decision + audit log
# ──────────────────────────────────────────────────────────────────────────────

def check_access(device_id: str, role: str) -> str:
    """
    Returns the visibility level for `role` on `device_id`, or "denied".

    v1.2 NOTE: the chaincode now consults BOTH the per-device and per-type
    policies; the returned level is the LEAST permissive of the two grants.
    """
    args = json.dumps({
        "function": "CheckAccess",
        "Args": [device_id, role],
    })
    out = _query(args)
    if out is None:
        return "denied"     # treat any query failure as denial (fail-closed)
    # Chaincode returns the bare string (no quotes) — but peer query may
    # add JSON-encoding depending on version. Strip optional quotes.
    return out.strip('"').strip()


def log_access(
    device_id: str, consumer: str, role: str,
    ts_ms: int, granted: bool, reason: str,
) -> bool:
    """
    Synchronous audit-log entry. Blocks ~500 ms for full Endorse→Order→Commit.
    Use log_access_async for latency-sensitive paths.
    """
    args = json.dumps({
        "function": "LogAccess",
        "Args": [
            device_id, consumer, role,
            str(ts_ms),
            "true" if granted else "false",
            reason,
        ],
    })
    return _invoke(args)


def log_access_async(
    device_id: str, consumer: str, role: str,
    ts_ms: int, granted: bool, reason: str,
) -> None:
    """
    Fire-and-forget LogAccess in a daemon thread.

    Returns immediately. The log entry is written ~500 ms later by the
    background thread. ⚠ Lost-on-crash window: if the API process crashes
    between the response and the chain commit, the entry is lost. Document
    this in the memoir as a known limitation of the demo-grade design.
    """
    def _worker():
        try:
            log_access(device_id, consumer, role, ts_ms, granted, reason)
        except Exception as e:
            log.warning("async LogAccess failed: %s", e)

    t = threading.Thread(target=_worker, daemon=True, name="LogAccess")
    t.start()


def get_access_log(device_id: str) -> list[dict]:
    """Return all audit-log entries for a given device, chronologically."""
    args = json.dumps({"function": "GetAccessLog", "Args": [device_id]})
    out = _query(args)
    if not out or out == "null":
        return []
    try:
        entries = json.loads(out)
        if not isinstance(entries, list):
            return []
        return entries
    except json.JSONDecodeError:
        return []


# ──────────────────────────────────────────────────────────────────────────────
# Smoke test — run this file directly to verify connectivity
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(name)s: %(message)s",
    )

    print("=== fabric_access smoke test ===")

    print("\n[1] Register device mote-92 (hum)...")
    ok = register_device(
        device_id="mote-92",
        owner_org="site-B",
        sensor_type="hum",
        readers=["owner", "analytics", "auditor", "admin"],
        visibility={
            "owner": "full",
            "analytics": "aggregated",
            "auditor": "hash-only",
            "admin": "full",
        },
    )
    print(f"    register_device → {ok}")

    print("\n[2] Register type policy for hum (permissive)...")
    ok = register_type_policy(
        sensor_type="hum",
        owner_org="site-B",
        readers=["owner", "analytics", "auditor", "admin"],
        visibility={
            "owner": "full",
            "analytics": "aggregated",
            "auditor": "hash-only",
            "admin": "full",
        },
    )
    print(f"    register_type_policy → {ok}")

    print("\n[3] CheckAccess(mote-92, analytics) → expect 'aggregated'")
    print(f"    → {check_access('mote-92', 'analytics')}")

    print("\n[4] Revoke analytics at type level...")
    ok = update_type_policy(
        sensor_type="hum",
        readers=["owner", "auditor", "admin"],
        visibility={
            "owner": "full",
            "auditor": "hash-only",
            "admin": "full",
        },
    )
    print(f"    update_type_policy → {ok}")
    time.sleep(2.5)  # wait one block cut

    print("\n[5] CheckAccess(mote-92, analytics) → expect 'denied'")
    print(f"    → {check_access('mote-92', 'analytics')}")

    print("\n=== smoke test complete ===")