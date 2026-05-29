"""
api/api.py — Integrity API (port 8080)
========================================

Serves the production read path for the IoT integrity pipeline:
  • /health, /login                              public
  • /devices, /readings, /reading/<id>           JWT-protected listing
  • /readings/<device_id>/<int:ts>/verify        manual forensic verify

──────────────────────────────────────────────────────────────────────────
The forensic /verify endpoint previously embedded its own `peer chaincode
query` subprocess and called VerifyHash with the v1.0/v1.1 signature
(3 args). After the chaincode v1.2 deploy of §31, that signature became
`VerifyHash(recordID, candidateHash)` — 2 args — so every forensic call
would now fail with "Expected 2, received 3".

This patch:
  1. Imports `fabric_access.verify_hash`, the v1.2-aware wrapper from §27.
  2. Pulls `seq` from the SQLite row and builds the composite record id
     `<device_id>_<ts>_<seq>` per §33.2's convention.
  3. Deletes the inline subprocess block (FABRIC_SAMPLES, _fabric_env,
     etc.) — the duplicated bridge code was what hid the drift from §33's
     audit. One bridge, one place to patch.
"""

import sqlite3
import sys
import time
from functools import wraps
from pathlib import Path

import jwt
from flask import Flask, request, jsonify
from flask_cors import CORS

# Allow `from fabric_access import …` — fabric_access.py is in the same
# api/ directory as this file (the v1.2-aware chaincode wrapper).
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fabric_access import verify_hash as _chain_verify_hash

DB_PATH = Path(__file__).resolve().parents[1] / "db" / "iot.db"

# Demo JWT secret — replace before any production use.
JWT_SECRET = "CHANGE_ME_SUPER_SECRET"
JWT_ALG    = "HS256"

app = Flask(__name__)
CORS(app)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def db_query(sql, args=(), one=False):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.execute(sql, args)
    rows = cur.fetchall()
    con.close()
    if one:
        return dict(rows[0]) if rows else None
    return [dict(r) for r in rows]


def make_record_id(device_id: str, timestamp: int, seq: int = 0) -> str:
    """
    Construct the deterministic ledger key for one reading.

    Mirrors `fabric_client.make_record_id` so the read and write paths key
    the ledger identically. See §33.2 of the session document for the
    triple-(device_id, ts, seq) convention and why `seq` is required for
    collision-free keys.
    """
    return f"{device_id}_{timestamp}_{seq}"


def require_jwt(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "missing token"}), 401
        token = auth.split(" ", 1)[1]
        try:
            jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except Exception:
            return jsonify({"error": "invalid token"}), 401
        return fn(*args, **kwargs)
    return wrapper


# ─────────────────────────────────────────────────────────────────────────────
# Public endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return jsonify({"ok": True})


@app.post("/login")
def login():
    """
    Demo authentication: username=admin password=admin.
    Replace with a proper users table for production.
    """
    data = request.json or {}
    if data.get("username") != "admin" or data.get("password") != "admin":
        return jsonify({"error": "bad credentials"}), 401

    now = int(time.time())
    payload = {"sub": "admin", "iat": now, "exp": now + 3600}
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    return jsonify({"token": token})


@app.get("/devices")
@require_jwt
def devices():
    """List devices + count of measurements."""
    rows = db_query("""
        SELECT device_id, COUNT(*) as n, MIN(ts) as first_ts, MAX(ts) as last_ts
        FROM readings
        GROUP BY device_id
        ORDER BY device_id
    """)
    return jsonify(rows)


# ─────────────────────────────────────────────────────────────────────────────
# /readings — STRICT MODE BY DEFAULT (Step 14)
#
# Trust boundary placement: verification is performed by the pipeline
# (ingestion + reverifier). The API just serves whatever verdict is stored
# in SQLite. No Fabric calls happen at request time → ~10 ms latency.
#
# Query parameters:
#   device_id (required)         which mote
#   limit     (default 200)      how many rows
#   strict    (default true)     true  → only verified='intact' rows
#                                false → all rows (forensic / audit view)
#
# Response shape:
#   {
#     "count":          12,
#     "strict":         true,
#     "hidden_summary": {"tampered": 2, "pending": 1},
#     "readings":       [ ... ]
#   }
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/readings")
@require_jwt
def readings():
    device_id = request.args.get("device_id")
    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    limit = int(request.args.get("limit", 200))
    limit = max(1, min(limit, 2000))   # clamp

    strict = request.args.get("strict", "true").lower() == "true"

    if strict:
        # Production path — only rows the pipeline has proven intact
        rows = db_query("""
            SELECT id, device_id, seq, ts, type, value, battery,
                   payload_hash, ingested_at, verified, verified_at
            FROM readings
            WHERE device_id = ? AND verified = 'intact'
            ORDER BY ts DESC
            LIMIT ?
        """, (device_id, limit))

        hidden = db_query("""
            SELECT verified, COUNT(*) AS c FROM readings
            WHERE device_id = ? AND verified != 'intact'
            GROUP BY verified
        """, (device_id,))
        hidden_summary = {row["verified"]: row["c"] for row in hidden}
    else:
        # Forensic mode — return everything with verdicts attached
        rows = db_query("""
            SELECT id, device_id, seq, ts, type, value, battery,
                   payload_hash, ingested_at, verified, verified_at
            FROM readings
            WHERE device_id = ?
            ORDER BY ts DESC
            LIMIT ?
        """, (device_id, limit))
        hidden_summary = {}

    return jsonify({
        "count":          len(rows),
        "strict":         strict,
        "hidden_summary": hidden_summary,
        "readings":       rows,
    })


@app.get("/reading/<int:rid>")
@require_jwt
def reading(rid: int):
    """Read full row including payload/raw."""
    row = db_query("SELECT * FROM readings WHERE id = ?", (rid,), one=True)
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(row)


# ─────────────────────────────────────────────────────────────────────────────
# Manual verify endpoint — PRESERVED for forensic/audit demonstrations.
#
# The pipeline (ingestion + reverifier) is the production verification path.
# This endpoint lets the user (or the jury) ask Fabric directly about a
# specific (device_id, ts) pair, bypassing the cached SQLite verdict.
# Useful when demonstrating the system end-to-end during the soutenance.
#
# v1.2 contract (POST-PATCH):
#   VerifyHash(recordID, candidateHash) — 2 args.
#   The composite record id is `<device_id>_<ts>_<seq>` and is built
#   client-side from the same SQLite row that provides `payload_hash`.
#   Calling fabric_access.verify_hash() reuses the wrapper that already
#   speaks the v1.2 contract, so a future v1.3 only requires a single
#   point of edit (fabric_access.py).
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/readings/<device_id>/<int:ts>/verify")
@require_jwt
def verify_reading(device_id, ts):
    row = db_query(
        "SELECT seq, payload_hash FROM readings WHERE device_id=? AND ts=?",
        (device_id, ts), one=True
    )
    if not row:
        return jsonify({"error": "not found"}), 404

    # `seq` is part of the schema since §33; legacy rows may have NULL.
    seq = int(row["seq"]) if row.get("seq") is not None else 0
    stored_hash = row["payload_hash"]
    record_id   = make_record_id(device_id, ts, seq)

    # Delegate to the v1.2-aware wrapper. Returns True if the on-chain
    # hash equals stored_hash, False on tamper / not-found / chain error.
    intact = _chain_verify_hash(record_id, stored_hash)

    return jsonify({
        "device_id":   device_id,
        "ts":          ts,
        "seq":         seq,
        "record_id":   record_id,
        "stored_hash": stored_hash,
        "intact":      intact,
    })


# ─────────────────────────────────────────────────────────────────────────────
# Removed (was the inline subprocess bridge for /verify):
#   import subprocess, os, json
#   FABRIC_SAMPLES, TEST_NETWORK, PEER_BIN, ORDERER_CA, ORG1_BASE constants
#   def _fabric_env()
#
# The duplication of fabric_client's bridge logic here is what allowed
# the drift in §34 to go unnoticed during §33's audit. Single bridge,
# single point of edit.
# ─────────────────────────────────────────────────────────────────────────────


if __name__ == "__main__":
    print("DB:", DB_PATH)
    app.run(host="0.0.0.0", port=8080, debug=True)
