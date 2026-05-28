import sqlite3
import time
from pathlib import Path
from functools import wraps

from flask import Flask, request, jsonify
import jwt

from flask_cors import CORS

DB_PATH = Path(__file__).resolve().parents[1] / "db" / "iot.db"

# change this for your project (JWT secret)
JWT_SECRET = "CHANGE_ME_SUPER_SECRET"
JWT_ALG    = "HS256"

app = Flask(__name__)
CORS(app)


def db_query(sql, args=(), one=False):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.execute(sql, args)
    rows = cur.fetchall()
    con.close()
    if one:
        return dict(rows[0]) if rows else None
    return [dict(r) for r in rows]


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
# Response shape (NEW — different from the old list-of-rows shape):
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
# ─────────────────────────────────────────────────────────────────────────────
import subprocess, os, json

FABRIC_SAMPLES = os.path.expanduser("~/hyperFabric/fabric-samples")
TEST_NETWORK   = os.path.join(FABRIC_SAMPLES, "test-network")
PEER_BIN       = os.path.join(FABRIC_SAMPLES, "bin", "peer")
ORDERER_CA     = os.path.join(TEST_NETWORK,
    "organizations/ordererOrganizations/example.com"
    "/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem")
ORG1_BASE      = os.path.join(TEST_NETWORK,
    "organizations/peerOrganizations/org1.example.com")


def _fabric_env():
    env = os.environ.copy()
    env["PATH"]                        = os.path.join(FABRIC_SAMPLES, "bin") + ":" + env.get("PATH", "")
    env["FABRIC_CFG_PATH"]             = os.path.join(FABRIC_SAMPLES, "config")
    env["CORE_PEER_TLS_ENABLED"]       = "true"
    env["CORE_PEER_LOCALMSPID"]        = "Org1MSP"
    env["CORE_PEER_ADDRESS"]           = "localhost:7051"
    env["CORE_PEER_TLS_ROOTCERT_FILE"] = f"{ORG1_BASE}/peers/peer0.org1.example.com/tls/ca.crt"
    env["CORE_PEER_MSPCONFIGPATH"]     = f"{ORG1_BASE}/users/Admin@org1.example.com/msp"
    return env


@app.get("/readings/<device_id>/<int:ts>/verify")
@require_jwt
def verify_reading(device_id, ts):
    row = db_query(
        "SELECT payload_hash FROM readings WHERE device_id=? AND ts=?",
        (device_id, ts), one=True
    )
    if not row:
        return jsonify({"error": "not found"}), 404

    stored_hash = row["payload_hash"]
    args = json.dumps({
        "function": "VerifyHash",
        "Args": [device_id, str(ts), stored_hash]
    })
    cmd = [
        PEER_BIN, "chaincode", "query",
        "--channelID", "mychannel",
        "--name",      "iot-integrity",
        "-c", args,
    ]
    try:
        result = subprocess.run(cmd, env=_fabric_env(),
                                capture_output=True, text=True, timeout=15)
        intact = result.stdout.strip().lower() == "true"
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({
        "device_id":   device_id,
        "ts":          ts,
        "stored_hash": stored_hash,
        "intact":      intact,
    })


if __name__ == "__main__":
    print("DB:", DB_PATH)
    app.run(host="0.0.0.0", port=8080, debug=True)