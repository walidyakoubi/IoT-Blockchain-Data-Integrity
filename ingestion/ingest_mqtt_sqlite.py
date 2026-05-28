import sys, os, hashlib, json, sqlite3, time
from pathlib import Path
import paho.mqtt.client as mqtt

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fabric_client import store_hash, verify_hash

MQTT_HOST    = "127.0.0.1"
MQTT_PORT    = 8883
CA_CERT_PATH = "/home/the_jacobi/iot-pipeline/infra/certs/ca.crt"
MQTT_TOPIC   = "iot/readings/#"
DB_PATH      = Path(__file__).resolve().parents[1] / "db" / "iot.db"


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _set_verdict(device_id: str, ts: int, seq: int, verdict: str):
    """
    Update the verdict of the exact row just processed.
    Filtering by (device_id, ts, seq) avoids overwriting siblings
    that happen to share device_id + ts (e.g. when ts has only
    second-resolution and two readings arrive in the same second).
    """
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "UPDATE readings "
        "SET verified=?, verified_at=? "
        "WHERE device_id=? AND ts=? AND seq=?",
        (verdict, int(time.time()), device_id, ts, seq),
    )
    con.commit()
    con.close()
    print(f"[Ingestion] {device_id} ts={ts} seq={seq} → {verdict}")


def insert_reading(msg: dict):
    payload   = json.dumps(msg, separators=(",", ":"), sort_keys=True)
    h         = sha256_hex(payload)
    device_id = str(msg.get("device_id"))
    ts        = int(msg.get("ts", 0))
    seq       = int(msg.get("seq", 0))

    # 1. Insert into SQLite as 'pending' — queryable but not yet verified
    con = sqlite3.connect(DB_PATH)
    con.execute(
        """
        INSERT INTO readings(device_id, seq, ts, type, value, battery,
                             raw, payload, payload_hash, ingested_at,
                             verified, verified_at)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            device_id,
            seq,
            ts,
            str(msg.get("type")),
            float(msg.get("value", 0.0)),
            int(msg.get("battery")) if msg.get("battery") is not None else None,
            str(msg.get("raw")) if msg.get("raw") is not None else None,
            payload,
            h,
            int(time.time()),
            "pending",
            0,
        ),
    )
    con.commit()
    con.close()
    print(f"[Ingestion] stored {device_id} ts={ts} seq={seq} "
          f"hash={h[:12]} → pending")

    # 2. Anchor on Fabric (~500 ms). seq is part of the ledger record_id
    #    so two readings with the same ts cannot collide on the ledger.
    if not store_hash(device_id, ts, h, seq):
        _set_verdict(device_id, ts, seq, "failed")
        return

    # 3. Round-trip verify — confirms what we anchored is what's there.
    intact  = verify_hash(device_id, ts, h, seq)
    verdict = "intact" if intact is True else (
              "tampered" if intact is False else "failed")
    _set_verdict(device_id, ts, seq, verdict)


def on_message(client, userdata, msg):
    print(f"[Ingestion] DEBUG received {msg.topic} ({len(msg.payload)} bytes)")
    try:
        data = json.loads(msg.payload)
        insert_reading(data)
    except Exception as e:
        import traceback
        print(f"[Ingestion] ❌ {type(e).__name__}: {e}")
        traceback.print_exc()


def main():
    c = mqtt.Client()
    c.on_message = on_message          
    c.tls_set(ca_certs=CA_CERT_PATH)
    c.tls_insecure_set(True)
    c.connect(MQTT_HOST, MQTT_PORT, 60)
    c.subscribe(MQTT_TOPIC)
    print(f"[Ingestion] subscribed to {MQTT_TOPIC}")
    print(f"[Ingestion] writing to DB: {DB_PATH}")
    c.loop_forever()


if __name__ == "__main__":
    main()