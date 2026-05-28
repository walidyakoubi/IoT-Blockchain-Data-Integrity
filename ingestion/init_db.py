import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parents[1] / "db" / "iot.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Schema with continuous-verification columns:
#   verified     ∈ {'pending', 'intact', 'tampered', 'failed'}
#                  - 'pending'  : freshly inserted, not yet anchored on Fabric
#                  - 'intact'   : anchored AND round-trip verified on Fabric
#                  - 'tampered' : Fabric returned False on VerifyHash
#                  - 'failed'   : Fabric was unreachable (transient — retry possible)
#   verified_at  = unix timestamp of the last verdict (0 = never verified)
#
# The compound index (device_id, verified) makes the API's hot query
#   WHERE device_id=? AND verified='intact'
# an O(log n) lookup even with millions of rows.
# ─────────────────────────────────────────────────────────────────────────────
schema = """
CREATE TABLE IF NOT EXISTS readings (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id     TEXT    NOT NULL,
  seq           INTEGER NOT NULL,
  ts            INTEGER NOT NULL,
  type          TEXT    NOT NULL,
  value         REAL    NOT NULL,
  battery       INTEGER,
  raw           TEXT,
  payload       TEXT    NOT NULL,
  payload_hash  TEXT    NOT NULL,
  ingested_at   INTEGER NOT NULL,
  verified      TEXT    DEFAULT 'pending',
  verified_at   INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_readings_device_ts       ON readings(device_id, ts);
CREATE INDEX IF NOT EXISTS idx_readings_verified        ON readings(verified);
CREATE INDEX IF NOT EXISTS idx_readings_device_verified ON readings(device_id, verified);
"""

con = sqlite3.connect(DB_PATH)
con.executescript(schema)
con.commit()
con.close()

print("✅ DB initialized:", DB_PATH)