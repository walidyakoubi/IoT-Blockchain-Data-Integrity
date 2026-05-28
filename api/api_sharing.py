"""
api/api_sharing.py
==================

Demonstration API for the backend IoT data sharing model.

Runs on PORT 5001 (separate from the main api.py on 5000) so the two coexist
and the data-sharing demonstration stays isolated from the existing pipeline.

Endpoints
---------
    POST /login                              JWT with role claim (any user)
    GET  /readings/full?device_id=X          owner / admin   — full data
    GET  /readings/aggregated?device_id=X    analytics / admin — hourly stats
    GET  /readings/verify?device_id=X        auditor / admin — hash + timestamp
    GET  /audit/<device_id>                  auditor / admin — on-chain access log
    GET  /policy/<device_id>                 any authenticated user
    PUT  /policy/<device_id>                 admin / owner
    POST /devices/register                   admin only
    GET  /policy/type/<sensor_type>          any authenticated user        (v1.2)
    POST /policy/type/<sensor_type>          admin only                    (v1.2)
    PUT  /policy/type/<sensor_type>          admin / owner                 (v1.2)

Demo user database (in-memory; for the PFE only — real systems use bcrypt + DB):
    alice   / alice123    / owner
    bob     / bob123      / analytics
    charlie / charlie123  / auditor
    admin   / admin123    / admin

Changelog
---------
2026-05-25  Fixed positional-argument mismatch in /devices/register.
            register_device() was updated to v1.2 (sensor_type added) in
            fabric_access.py but the call site here was not. Symptom:
            HTTP 500 with TypeError "missing 1 required positional
            argument: 'visibility'".

            Default readers/visibility now include the admin role so that
            registering a device through the dashboard produces an
            immediately-usable policy.

            Added optional v1.2 type-policy endpoints (POST/GET/PUT
            /policy/type/<sensor_type>) with graceful degradation if the
            v1.2 wrappers are not present in fabric_access.py.
"""

import datetime as _dt
import sqlite3
import sys
import time
from collections import defaultdict
from functools import wraps
from pathlib import Path

import jwt
from flask import Flask, g, jsonify, request

from flask_cors import CORS

# Import the chaincode wrappers from the same project tree.
# This file is in   ~/iot-pipeline/api/api_sharing.py
# fabric_access.py is in   ~/iot-pipeline/api/   (same dir)
sys.path.insert(0, str(Path(__file__).resolve().parent))
from fabric_access import (
    check_access,
    get_access_log,
    get_policy,
    log_access_async,
    register_device,
    update_policy,
)

# v1.2 type-policy wrappers — optional. If fabric_access.py has not yet been
# upgraded with these three functions, the type-policy endpoints below will
# return HTTP 501 (Not Implemented) instead of crashing the whole API.
try:
    from fabric_access import (
        get_type_policy,
        register_type_policy,
        update_type_policy,
    )
    _HAS_TYPE_POLICY = True
except ImportError:
    _HAS_TYPE_POLICY = False


# =============================================================================
# Configuration
# =============================================================================
JWT_SECRET   = "pfe-demo-secret-require-replace-in-production-2026"   # demo only
JWT_ALG      = "HS256"
TOKEN_TTL_S  = 3600
DB_PATH      = Path(__file__).resolve().parents[1] / "db" / "iot.db"
LISTEN_PORT  = 5001

USERS = {
    "alice":   {"password": "alice123",   "role": "owner"},
    "bob":     {"password": "bob123",     "role": "analytics"},
    "charlie": {"password": "charlie123", "role": "auditor"},
    "admin":   {"password": "admin123",   "role": "admin"},
}

app = Flask(__name__)

# CORS — broad in development, allows :3001 (dashboard) to call :5001 (API).
# allow_headers + methods make preflights succeed for PUT/POST too, which the
# default CORS(app) call was not handling reliably on every route.
CORS(
    app,
    resources={r"/*": {"origins": "*"}},
    allow_headers=["Authorization", "Content-Type"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    supports_credentials=False,
)


# =============================================================================
# Helpers
# =============================================================================

def db_query(sql: str, args=(), one: bool = False):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    cur = con.execute(sql, args)
    rv = cur.fetchall()
    con.close()
    return (rv[0] if rv else None) if one else rv


def issue_token(username: str, role: str) -> str:
    payload = {
        "sub":  username,
        "role": role,
        "iat":  int(time.time()),
        "exp":  int(time.time()) + TOKEN_TTL_S,
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def _decode_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:]
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.PyJWTError:
        return None


def require_auth(allowed_roles=None):
    """Decorator: validate JWT and optionally restrict to a role whitelist."""
    def deco(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            payload = _decode_token()
            if payload is None:
                return jsonify({"error": "unauthorized"}), 401
            if allowed_roles and payload.get("role") not in allowed_roles:
                return jsonify({
                    "error":         "forbidden",
                    "required_role": allowed_roles,
                    "your_role":     payload.get("role"),
                }), 403
            g.user = payload
            return f(*args, **kwargs)
        return wrapper
    return deco


def now_ms() -> int:
    return int(time.time() * 1000)


def _enforce_chain_access(device_id: str, expected_level: str):
    """
    Calls CheckAccess on chaincode and (asynchronously) writes a LogAccess
    entry for every decision — granted or denied.
    Returns (granted: bool, level: str).
    """
    user     = g.user
    role     = user["role"]
    consumer = user["sub"]
    level    = check_access(device_id, role)
    granted  = (level == expected_level)
    reason   = f"requested={expected_level} chain_returned={level}"
    log_access_async(device_id, consumer, role, now_ms(), granted, reason)
    return granted, level


# =============================================================================
# Endpoints
# =============================================================================

@app.get("/health")
def health():
    return jsonify({
        "status":          "ok",
        "service":         "api_sharing",
        "port":            LISTEN_PORT,
        "type_policy_v12": _HAS_TYPE_POLICY,
        "note":            "data sharing demo API",
    })


@app.post("/login")
def login():
    data     = request.get_json(silent=True) or {}
    username = data.get("username")
    password = data.get("password")
    user     = USERS.get(username)
    if not user or user["password"] != password:
        return jsonify({"error": "invalid credentials"}), 401
    return jsonify({
        "access_token": issue_token(username, user["role"]),
        "username":     username,
        "role":         user["role"],
        "expires_in":   TOKEN_TTL_S,
    })


# ---------- READINGS ENDPOINTS -----------------------------------------------

@app.get("/readings/full")
@require_auth(allowed_roles=["owner", "admin"])
def readings_full():
    device_id = request.args.get("device_id")
    limit     = int(request.args.get("limit", 100))
    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    granted, level = _enforce_chain_access(device_id, "full")
    if not granted:
        return jsonify({
            "error":      "denied by chaincode policy",
            "chain_says": level,
        }), 403

    rows = db_query(
        "SELECT device_id, ts, type, value, payload_hash, verified "
        "FROM readings WHERE device_id=? ORDER BY ts DESC LIMIT ?",
        (device_id, limit),
    )
    return jsonify({
        "device_id": device_id,
        "level":     "full",
        "count":     len(rows),
        "readings":  [dict(r) for r in rows],
    })


@app.get("/readings/aggregated")
@require_auth(allowed_roles=["analytics", "admin"])
def readings_aggregated():
    device_id = request.args.get("device_id")
    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    granted, level = _enforce_chain_access(device_id, "aggregated")
    if not granted:
        return jsonify({
            "error":      "denied by chaincode policy",
            "chain_says": level,
        }), 403

    rows = db_query(
        "SELECT ts, value FROM readings "
        "WHERE device_id=? ORDER BY ts DESC LIMIT 1000",
        (device_id,),
    )
    # Aggregate by hour (UTC). Aggregation is the *only* projection — no raw values returned.
    buckets = defaultdict(list)
    for r in rows:
        try:
            ts  = int(r["ts"])
            val = float(r["value"])
        except (TypeError, ValueError):
            continue
        hour = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).strftime("%Y-%m-%dT%H:00Z")
        buckets[hour].append(val)

    aggregates = []
    for hour in sorted(buckets.keys(), reverse=True):
        values = buckets[hour]
        aggregates.append({
            "hour":  hour,
            "count": len(values),
            "avg":   round(sum(values) / len(values), 3),
            "min":   round(min(values), 3),
            "max":   round(max(values), 3),
        })
    return jsonify({
        "device_id":     device_id,
        "level":         "aggregated",
        "bucket_count":  len(aggregates),
        "buckets":       aggregates,
    })


@app.get("/readings/verify")
@require_auth(allowed_roles=["auditor", "admin"])
def readings_verify():
    device_id = request.args.get("device_id")
    limit     = int(request.args.get("limit", 100))
    if not device_id:
        return jsonify({"error": "device_id required"}), 400

    granted, level = _enforce_chain_access(device_id, "hash-only")
    if not granted:
        return jsonify({
            "error":      "denied by chaincode policy",
            "chain_says": level,
        }), 403

    rows = db_query(
        "SELECT ts, payload_hash, verified FROM readings "
        "WHERE device_id=? ORDER BY ts DESC LIMIT ?",
        (device_id, limit),
    )
    return jsonify({
        "device_id": device_id,
        "level":     "hash-only",
        "count":     len(rows),
        "hashes":    [dict(r) for r in rows],
    })


# ---------- AUDIT + POLICY ENDPOINTS -----------------------------------------

@app.get("/audit/<device_id>")
@require_auth(allowed_roles=["auditor", "admin"])
def audit_log(device_id):
    """On-chain audit trail of every access decision (granted and denied)."""
    entries = get_access_log(device_id)
    return jsonify({
        "device_id": device_id,
        "count":     len(entries),
        "log":       entries,
    })


@app.get("/policy/<device_id>")
@require_auth()
def view_policy(device_id):
    policy = get_policy(device_id)
    if policy is None:
        return jsonify({"error": "no policy registered", "device_id": device_id}), 404
    return jsonify(policy)


@app.put("/policy/<device_id>")
@require_auth(allowed_roles=["admin", "owner"])
def change_policy(device_id):
    data       = request.get_json(silent=True) or {}
    readers    = data.get("readers")
    visibility = data.get("visibility")
    if not isinstance(readers, list) or not isinstance(visibility, dict):
        return jsonify({"error": "body must include readers[] and visibility{}"}), 400
    if not update_policy(device_id, readers, visibility):
        return jsonify({"error": "policy update failed on chain"}), 500
    return jsonify({"status": "updated", "device_id": device_id})


@app.post("/devices/register")
@require_auth(allowed_roles=["admin"])
def add_device():
    data        = request.get_json(silent=True) or {}
    device_id   = data.get("device_id")
    owner_org   = data.get("owner_org", "site-A")
    # ── v1.2: chaincode now tracks sensor_type on the device record. ──
    # "" preserves v1.1 backward compatibility (device-only policy, no type).
    sensor_type = data.get("sensor_type", "")
    # Admin is now part of the defaults so a freshly-registered device is
    # immediately usable from the admin dashboard without an extra PUT step.
    readers     = data.get("readers", ["owner", "analytics", "auditor", "admin"])
    visibility  = data.get("visibility", {
        "owner":     "full",
        "analytics": "aggregated",
        "auditor":   "hash-only",
        "admin":     "full",
    })
    if not device_id:
        return jsonify({"error": "device_id required"}), 400
    # fabric_access.register_device() v1.2 signature is:
    #   register_device(device_id, owner_org, sensor_type, readers, visibility)
    # Calling it with 4 args (the v1.1 form) shifts every argument one slot
    # to the left and triggers a TypeError on 'visibility' — see Changelog.
    if not register_device(device_id, owner_org, sensor_type, readers, visibility):
        return jsonify({"error": "registration failed on chain"}), 500
    return jsonify({
        "status":      "registered",
        "device_id":   device_id,
        "sensor_type": sensor_type or "(none / legacy)",
    })


# ---------- v1.2: TYPE-POLICY ENDPOINTS --------------------------------------
# These complement the per-device policy. The chaincode composes both with
# AND-and-least-permissive semantics (see Section 31 of the project notes).
# If fabric_access.py is still v1.1 and does not export the type-policy
# wrappers, these endpoints return 501 rather than crashing on import.

def _type_policy_not_available():
    return jsonify({
        "error": "type-policy wrappers not available in fabric_access.py",
        "hint":  "upgrade fabric_access.py to v1.2 (register_type_policy / "
                 "get_type_policy / update_type_policy)",
    }), 501


@app.get("/policy/type/<sensor_type>")
@require_auth()
def view_type_policy(sensor_type):
    if not _HAS_TYPE_POLICY:
        return _type_policy_not_available()
    policy = get_type_policy(sensor_type)
    if policy is None:
        return jsonify({
            "error":       "no policy registered for type",
            "sensor_type": sensor_type,
        }), 404
    return jsonify(policy)


@app.post("/policy/type/<sensor_type>")
@require_auth(allowed_roles=["admin"])
def register_type_policy_route(sensor_type):
    if not _HAS_TYPE_POLICY:
        return _type_policy_not_available()
    data       = request.get_json(silent=True) or {}
    owner_org  = data.get("owner_org", "site-A")
    readers    = data.get("readers")
    visibility = data.get("visibility")
    if not isinstance(readers, list) or not isinstance(visibility, dict):
        return jsonify({"error": "body must include readers[] and visibility{}"}), 400
    if not register_type_policy(sensor_type, owner_org, readers, visibility):
        return jsonify({"error": "type policy registration failed on chain"}), 500
    return jsonify({"status": "registered", "sensor_type": sensor_type})


@app.put("/policy/type/<sensor_type>")
@require_auth(allowed_roles=["admin", "owner"])
def change_type_policy(sensor_type):
    if not _HAS_TYPE_POLICY:
        return _type_policy_not_available()
    data       = request.get_json(silent=True) or {}
    readers    = data.get("readers")
    visibility = data.get("visibility")
    if not isinstance(readers, list) or not isinstance(visibility, dict):
        return jsonify({"error": "body must include readers[] and visibility{}"}), 400
    if not update_type_policy(sensor_type, readers, visibility):
        return jsonify({"error": "type policy update failed on chain"}), 500
    return jsonify({"status": "updated", "sensor_type": sensor_type})


# =============================================================================
# Startup banner
# =============================================================================

def _print_banner():
    print("=" * 72)
    print(f"  Data Sharing API — listening on port {LISTEN_PORT}")
    print("=" * 72)
    print("  Endpoints:")
    print("    POST /login                              (any user)")
    print("    GET  /readings/full?device_id=X          (owner / admin)")
    print("    GET  /readings/aggregated?device_id=X    (analytics / admin)")
    print("    GET  /readings/verify?device_id=X        (auditor / admin)")
    print("    GET  /audit/<device_id>                  (auditor / admin)")
    print("    GET  /policy/<device_id>                 (any authenticated)")
    print("    PUT  /policy/<device_id>                 (admin / owner)")
    print("    POST /devices/register                   (admin)")
    if _HAS_TYPE_POLICY:
        print("    GET  /policy/type/<sensor_type>          (any authenticated)  [v1.2]")
        print("    POST /policy/type/<sensor_type>          (admin)              [v1.2]")
        print("    PUT  /policy/type/<sensor_type>          (admin / owner)      [v1.2]")
    else:
        print("    /policy/type/* endpoints disabled — fabric_access.py is v1.1")
    print()
    print("  Demo users:")
    for u, info in USERS.items():
        print(f"    {u:8s}  password={info['password']:12s}  role={info['role']}")
    print("=" * 72)


if __name__ == "__main__":
    _print_banner()
    app.run(host="0.0.0.0", port=LISTEN_PORT)