"""
key_manager.py
HKDF-based key derivation from a single master secret.
derives K_enc (AES-128 key) per device.
"""
import hashlib, hmac, os
from pathlib import Path

MASTER_KEY_FILE = Path(__file__).parent / "master.key"
HKDF_SALT       = b"iot-fabric-auth-v1"   # domain separator — never change


def load_or_create_master_key() -> bytes:
    if MASTER_KEY_FILE.exists():
        key = bytes.fromhex(MASTER_KEY_FILE.read_text().strip())
        print(f"[KeyManager] Master key loaded.")
        return key
    master = os.urandom(32)
    MASTER_KEY_FILE.write_text(master.hex())
    MASTER_KEY_FILE.chmod(0o600)
    print(f"[KeyManager] ⚠️  New master key generated → {MASTER_KEY_FILE}")
    print(f"[KeyManager]    Flash this hex to ALL motes before deployment.")
    return master


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    """HKDF-Expand (RFC 5869 §2.3), single-block since length ≤ 32."""
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def derive_enc_key(master_key: bytes, device_id: str) -> bytes:
    """
    Derive the 128-bit AES-CCM key for a device.
    Same master_key + device_id → always the same K_enc (deterministic).
    """
    prk  = hmac.new(HKDF_SALT, master_key, hashlib.sha256).digest()
    info = f"device:{device_id}|enc".encode()
    return _hkdf_expand(prk, info, 16)      # AES-128 → 16 bytes