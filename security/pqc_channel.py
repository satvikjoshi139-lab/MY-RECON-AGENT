"""
security/pqc_channel.py

PQC Secure Channel — agent-to-agent, agent-to-LLM, LLM-to-agent.

Real mode:  ML-KEM-512 (pqcrypto) + AES-256-GCM
Fallback:   HKDF-derived AES-256-GCM (all features, no quantum-resistance)

Every `send_secure()` call:
  1. Serialises the packet to JSON bytes
  2. Encrypts with the receiver's public key
  3. Decrypts with the receiver's private key  (proves round-trip)
  4. Logs the hop for the dashboard
"""
import json
import os
import secrets
import time
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

NONCE_LEN  = 12
KEM_CT_LEN = 768

try:
    from pqcrypto.kem.ml_kem_512 import (
        generate_keypair,
        encrypt as kem_encrypt,
        decrypt as kem_decrypt,
    )
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False


# ── Key pair ──────────────────────────────────────────────────────────────────

class PQCKeyPair:
    """One keypair per agent. AES fallback uses proper HKDF derivation."""

    def __init__(self, agent_name: str):
        self.agent_name = agent_name
        if PQC_AVAILABLE:
            self.pub, self.priv = generate_keypair()
            self._shared_secret = None          # computed at encrypt time
        else:
            # Generate a proper random 32-byte secret for AES
            self._secret = os.urandom(32)
            # Dummy pub/priv (same length as ML-KEM-512 for compatibility)
            self.pub  = self._secret + os.urandom(768)   # 800 bytes total
            self.priv = self._secret + os.urandom(1600)  # 1632 bytes total

    @property
    def aes_key(self) -> bytes:
        """Derive a stable AES key from the secret via HKDF."""
        return HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"sentinelx-aes-key",
            backend=default_backend(),
        ).derive(self._secret)


# ── Encrypt / Decrypt ─────────────────────────────────────────────────────────

def _encrypt(keypair: "PQCKeyPair", plaintext: bytes) -> bytes:
    if PQC_AVAILABLE:
        kem_ct, shared = kem_encrypt(keypair.pub)
        aes_key = shared[:32]
    else:
        kem_ct  = secrets.token_bytes(KEM_CT_LEN)   # placeholder
        aes_key = keypair.aes_key

    nonce = secrets.token_bytes(NONCE_LEN)
    ct    = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    return kem_ct + nonce + ct


def _decrypt(keypair: "PQCKeyPair", blob: bytes) -> bytes:
    kem_ct = blob[:KEM_CT_LEN]
    nonce  = blob[KEM_CT_LEN : KEM_CT_LEN + NONCE_LEN]
    ct     = blob[KEM_CT_LEN + NONCE_LEN :]

    if PQC_AVAILABLE:
        shared  = kem_decrypt(keypair.priv, kem_ct)
        aes_key = shared[:32]
    else:
        aes_key = keypair.aes_key          # same derivation as encrypt

    return AESGCM(aes_key).decrypt(nonce, ct, None)


# ── Channel log ───────────────────────────────────────────────────────────────

_channel_log: list[dict] = []


def send_secure(
    sender: str,
    receiver: str,
    receiver_keypair: "PQCKeyPair",
    packet: dict,
) -> dict:
    """Encrypt packet for receiver, decrypt it, log the hop, return packet."""
    t0        = time.perf_counter()
    plaintext = json.dumps(packet, default=str).encode()
    encrypted = _encrypt(receiver_keypair, plaintext)
    decrypted = _decrypt(receiver_keypair, encrypted)
    elapsed   = round((time.perf_counter() - t0) * 1000, 2)

    mode = "ML-KEM-512 + AES-256-GCM" if PQC_AVAILABLE else "HKDF + AES-256-GCM"

    _channel_log.append({
        "from"     : sender,
        "to"       : receiver,
        "mode"     : mode,
        "bytes"    : len(encrypted),
        "ms"       : elapsed,
        "timestamp": time.strftime("%H:%M:%S"),
        "verified" : (decrypted == plaintext),
    })

    return json.loads(decrypted.decode())


def get_channel_log() -> list[dict]:
    return list(_channel_log)


def clear_channel_log():
    _channel_log.clear()
