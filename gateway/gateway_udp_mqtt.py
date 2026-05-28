"""
gateway_udp_mqtt.py — Multi-DODAG aware IoT gateway (Option G1)
=======================================================

Architecture
------------
One gateway process per data type, parameterised by two environment variables:
    GATEWAY_BIND   IPv6 address to bind the UDP socket to
                   (e.g. "aaaa::1", "bbbb::1", "cccc::1")
    GATEWAY_TYPE   Expected sensor type for this gateway instance
                   (e.g. "temp", "hum", "press")
Both default to permissive values so the file also runs in legacy G2 mode.

Defense in depth — every packet passes three independent checks
---------------------------------------------------------------
    1. AAD type cross-check    — AAD-authenticated `type` field must match
                                 this gateway's GATEWAY_TYPE.
    2. Replay protection       — per-device monotonically increasing seq.
    3. AES-CCM-8 tag           — authenticated decryption (PyCryptodome).
Any failure drops the packet with a distinct log entry.

Wire format (UDP, ASCII)
------------------------
    id=N;seq=M;type=T;nonce=<hex>;ct=<hex>;tag=<hex>
    └──────────── AAD (authenticated cleartext) ──────────┘└─ tag ─┘

Example invocations
-------------------
    GATEWAY_BIND=aaaa::1 GATEWAY_TYPE=temp  python3 gateway.py
    GATEWAY_BIND=bbbb::1 GATEWAY_TYPE=hum   python3 gateway.py
    GATEWAY_BIND=cccc::1 GATEWAY_TYPE=press python3 gateway.py
    python3 gateway.py                       # legacy G2 (wildcard, any type)
"""

import os
import re
import socket
import json
import time
import logging
from typing import Dict, Optional

from Crypto.Cipher import AES                # pip install pycryptodome
import paho.mqtt.client as mqtt

from key_manager import load_or_create_master_key, derive_enc_key


# ─── G1 parameters (from environment) ─────────────────────────────────────────
GATEWAY_BIND = os.environ.get("GATEWAY_BIND", "::")     # wildcard if unset
GATEWAY_TYPE = os.environ.get("GATEWAY_TYPE", "")        # empty = accept any

# ─── Static configuration ─────────────────────────────────────────────────────
UDP_PORT     = 3000
MQTT_HOST    = "127.0.0.1"
MQTT_PORT    = 8883
MQTT_CA_FILE = os.path.expanduser("~/iot-pipeline/infra/certs/ca.crt")
TOPIC_PREFIX = "iot/readings"

TAG_LEN     = 8     # CCM-8
AES_KEY_LEN = 16    # AES-128
NONCE_LEN   = 13    # CCM with L=2

# ─── Logging — gateway tag in every line ──────────────────────────────────────
GATEWAY_TAG = GATEWAY_TYPE if GATEWAY_TYPE else "any"
logging.basicConfig(
    level=logging.INFO,
    format=f"[Gateway/{GATEWAY_TAG}] %(message)s",
)
log = logging.getLogger("gateway")

# ─── Master key + per-device replay window ────────────────────────────────────
MASTER_KEY = load_or_create_master_key()
last_seq: Dict[str, int] = {}


# ─── Wire-format parsers (Step 17 multi-type + Step 13 legacy fallback) ───────
PAT_NEW = re.compile(
    r"id=(\d+);seq=(\d+);type=(\w+);"
    r"nonce=([0-9a-f]+);ct=([0-9a-f]*);tag=([0-9a-f]+)"
)
PAT_OLD = re.compile(
    r"id=(\d+);seq=(\d+);"
    r"nonce=([0-9a-f]+);ct=([0-9a-f]*);tag=([0-9a-f]+)"
)
PAT_BODY = re.compile(
    r"(?:v|temp|hum|press)=(-?\d+(?:\.\d+)?);batt=(\d+)"
)


def parse_frame(text: str) -> Optional[dict]:
    """
    Decode one ASCII wire frame. Tries the multi-type format first, then
    the legacy single-type format. Returns None on malformed input.
    The reconstructed `ad` MUST be byte-identical to what the mote
    authenticated, or AES-CCM tag verification will fail.
    """
    text = text.strip()
    m = PAT_NEW.fullmatch(text)
    if m:
        n, seq_str, ftype, nonce_hex, ct_hex, tag_hex = m.groups()
        return {
            "device_id": f"mote-{n}",
            "seq":       int(seq_str),
            "type":      ftype,
            "nonce":     bytes.fromhex(nonce_hex),
            "ciphertext": bytes.fromhex(ct_hex),
            "tag":       bytes.fromhex(tag_hex),
            "ad":        f"id={n};seq={seq_str};type={ftype}".encode("ascii"),
        }

    m = PAT_OLD.fullmatch(text)
    if m:
        n, seq_str, nonce_hex, ct_hex, tag_hex = m.groups()
        return {
            "device_id": f"mote-{n}",
            "seq":       int(seq_str),
            "type":      "temp",                  # legacy firmware = temp only
            "nonce":     bytes.fromhex(nonce_hex),
            "ciphertext": bytes.fromhex(ct_hex),
            "tag":       bytes.fromhex(tag_hex),
            "ad":        f"id={n};seq={seq_str}".encode("ascii"),
        }

    return None


def decrypt_and_verify(frame: dict) -> Optional[bytes]:
    """AES-CCM-8 decryption + tag verification with AAD. Atomic."""
    key = derive_enc_key(MASTER_KEY, frame["device_id"])
    try:
        cipher = AES.new(key, AES.MODE_CCM,
                         nonce=frame["nonce"], mac_len=TAG_LEN)
        cipher.update(frame["ad"])
        return cipher.decrypt_and_verify(frame["ciphertext"], frame["tag"])
    except (ValueError, KeyError):
        return None


def parse_body(plaintext: bytes) -> Optional[dict]:
    """Extract value and batt from decrypted body."""
    try:
        s = plaintext.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    m = PAT_BODY.fullmatch(s)
    if not m:
        return None
    return {"value": float(m.group(1)), "batt": int(m.group(2))}


# ─── MQTT setup ───────────────────────────────────────────────────────────────
def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        log.info("MQTT connected to %s:%d", MQTT_HOST, MQTT_PORT)
    else:
        log.error("MQTT connection failed (rc=%d)", rc)


def setup_mqtt() -> mqtt.Client:
    mc = mqtt.Client(client_id=f"gateway-{GATEWAY_TAG}", clean_session=True)
    mc.tls_set(ca_certs=MQTT_CA_FILE)
    mc.tls_insecure_set(True)
    mc.on_connect = on_connect
    mc.connect(MQTT_HOST, MQTT_PORT, keepalive=30)
    mc.loop_start()    # background thread handles network I/O + reconnects
    return mc


# ─── Main loop ────────────────────────────────────────────────────────────────
def main():
    log.info("AES-CCM-8 active — multi-type sensors supported")
    log.info("G1 mode: GATEWAY_BIND=%s GATEWAY_TYPE=%s",
             GATEWAY_BIND, GATEWAY_TYPE or "(any)")

    mc = setup_mqtt()

    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((GATEWAY_BIND, UDP_PORT))

    log.info("Listening UDP/IPv6 [%s]:%d, publishing to %s/%s/<dev>",
             GATEWAY_BIND, UDP_PORT,
             TOPIC_PREFIX, GATEWAY_TYPE if GATEWAY_TYPE else "<type>")

    try:
        while True:
            data, addr = sock.recvfrom(2048)
            try:
                text = data.decode("ascii", errors="replace")
            except Exception:
                continue

            frame = parse_frame(text)
            if frame is None:
                log.warning("Malformed frame from %s: %r", addr[0], text[:80])
                continue

            # ── Layer 1: AAD type cross-check ────────────────────────────
            if GATEWAY_TYPE and frame["type"] != GATEWAY_TYPE:
                log.warning(
                    "Type mismatch from %s seq=%d: AAD says type=%s, "
                    "this gateway expects %s — dropping",
                    frame["device_id"], frame["seq"],
                    frame["type"], GATEWAY_TYPE,
                )
                continue

            # ── Layer 2: replay protection ────────────────────────────────
            prev = last_seq.get(frame["device_id"], -1)
            if frame["seq"] <= prev:
                log.warning(
                    "Replay rejected from %s: seq=%d <= last_seq=%d",
                    frame["device_id"], frame["seq"], prev,
                )
                continue

            # ── Layer 3: AES-CCM-8 tag verification ──────────────────────
            plaintext = decrypt_and_verify(frame)
            if plaintext is None:
                log.warning(
                    "Tag verification failed from %s seq=%d — dropping",
                    frame["device_id"], frame["seq"],
                )
                continue

            # ── Body parse (after all security checks pass) ──────────────
            body = parse_body(plaintext)
            if body is None:
                log.warning(
                    "Malformed body from %s seq=%d: %r",
                    frame["device_id"], frame["seq"], plaintext[:80],
                )
                continue

            # ── Accept + advance replay window + publish ─────────────────
            last_seq[frame["device_id"]] = frame["seq"]

            log.info(
                "✅ decrypted [%s] type=%s value=%s batt=%d seq=%d",
                frame["device_id"], frame["type"],
                body["value"], body["batt"], frame["seq"],
            )

            payload = {
                "device_id": frame["device_id"],
                "type":      frame["type"],
                "value":     body["value"],
                "battery":   body["batt"],
                "seq":       frame["seq"],
                "ts":        int(time.time() * 1000),   
            }
            topic = f"{TOPIC_PREFIX}/{frame['type']}/{frame['device_id']}"
            mc.publish(topic, json.dumps(payload), qos=1)

    except KeyboardInterrupt:
        log.info("Shutting down (Ctrl-C received)")
    finally:
        mc.loop_stop()
        mc.disconnect()
        sock.close()


if __name__ == "__main__":
    main()