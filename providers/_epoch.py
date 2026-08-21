# providers/_epoch.py
# Epoch ECDH + KDF Chain — forward secrecy layer.
# Mirror of agents/native/rust/src/epoch.rs. Cross-language compatibility is critical.

import hashlib
import hmac as _hmac
import json
import os
import struct
from dataclasses import dataclass, field
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

VERSION_BYTE = 0x02
MAX_SKIP = 10


@dataclass
class EpochState:
    epoch: int = 0
    epoch_key: bytes = b""
    chain_key: bytes = b""
    counter: int = 0
    server_eph_priv: bytes = b""
    server_eph_pub: bytes = b""
    agent_eph_pub: bytes = b""
    prekey_privs: list = field(default_factory=list)
    prev_epoch_key: Optional[bytes] = None


def _hkdf_derive(ikm: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(ikm)


def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


def _gcm_seal(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def _gcm_open(key: bytes, blob: bytes) -> Optional[bytes]:
    if len(blob) < 28:
        return None
    try:
        return AESGCM(key).decrypt(blob[:12], blob[12:], None)
    except Exception:
        return None


def generate_prekey_pool(n: int = 8) -> list:
    pool = []
    for _ in range(n):
        priv_key = X25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        priv_bytes = priv_key.private_bytes_raw()
        pub_bytes = pub_key.public_bytes_raw()
        pool.append((priv_bytes, pub_bytes))
    return pool


def _x25519_dh(my_priv: bytes, their_pub: bytes) -> bytes:
    priv_key = X25519PrivateKey.from_private_bytes(my_priv)
    pub_key = X25519PublicKey.from_public_bytes(their_pub)
    return priv_key.exchange(pub_key)


def _gen_ephemeral() -> tuple:
    priv_key = X25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    return priv_key.private_bytes_raw(), pub_key.public_bytes_raw()


def bootstrap_epoch_server(
    prekey_priv: bytes,
    agent_eph_pub: bytes,
    session_key: bytes,
    agent_id: bytes,
) -> EpochState:
    shared = _x25519_dh(prekey_priv, agent_eph_pub)
    epoch_key = _hkdf_derive(shared, session_key, b"stratum-epoch-0")
    chain_key = _hkdf_derive(epoch_key, agent_id, b"stratum-chain-v1")
    server_priv, server_pub = _gen_ephemeral()

    return EpochState(
        epoch=0,
        epoch_key=epoch_key,
        chain_key=chain_key,
        counter=0,
        server_eph_priv=server_priv,
        server_eph_pub=server_pub,
        agent_eph_pub=agent_eph_pub,
    )


def rotate_epoch_server(state: EpochState, agent_eph_pub: bytes, agent_id: bytes):
    shared = _x25519_dh(state.server_eph_priv, agent_eph_pub)
    new_epoch = state.epoch + 1
    info_str = f"stratum-epoch-{new_epoch}".encode()
    new_epoch_key = _hkdf_derive(shared, state.epoch_key, info_str)
    new_chain_key = _hkdf_derive(new_epoch_key, agent_id, b"stratum-chain-v1")
    new_priv, new_pub = _gen_ephemeral()

    state.prev_epoch_key = state.epoch_key
    state.epoch = new_epoch
    state.epoch_key = new_epoch_key
    state.chain_key = new_chain_key
    state.counter = 0
    state.server_eph_priv = new_priv
    state.server_eph_pub = new_pub
    state.agent_eph_pub = agent_eph_pub


def chain_advance(state: EpochState, payload: bytes) -> tuple:
    msg_key = _hmac_sha256(state.chain_key, b"\x01")
    state.chain_key = _hmac_sha256(state.chain_key, b"\x02")
    counter = state.counter
    state.counter += 1

    tag_input = struct.pack("<Q", counter) + payload
    tag = _hmac_sha256(msg_key, tag_input)
    return tag, counter


def chain_verify(state: EpochState, claimed_counter: int,
                 payload: bytes, claimed_tag: bytes) -> bool:
    if claimed_counter < state.counter:
        return False
    if claimed_counter > state.counter + MAX_SKIP:
        return False

    tmp_chain = state.chain_key
    tmp_counter = state.counter

    while tmp_counter < claimed_counter:
        _msg_key = _hmac_sha256(tmp_chain, b"\x01")
        tmp_chain = _hmac_sha256(tmp_chain, b"\x02")
        tmp_counter += 1

    msg_key = _hmac_sha256(tmp_chain, b"\x01")
    next_chain = _hmac_sha256(tmp_chain, b"\x02")

    tag_input = struct.pack("<Q", claimed_counter) + payload
    expected = _hmac_sha256(msg_key, tag_input)

    if expected == claimed_tag:
        state.chain_key = next_chain
        state.counter = claimed_counter + 1
        return True
    return False


def encrypt_command_v2(
    task_json: str,
    key_file: str,
    state: EpochState,
    key_password: Optional[bytes] = None,
) -> bytes:
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    from cryptography.hazmat.primitives.asymmetric import padding as _asym_padding
    from pathlib import Path

    priv_key = load_pem_private_key(Path(key_file).read_bytes(), password=key_password)
    aes_key = os.urandom(32)
    payload_blob = _gcm_seal(aes_key, task_json.encode())
    wrapped_aes = _gcm_seal(state.epoch_key, aes_key)

    sig_msg = wrapped_aes + payload_blob
    sig = priv_key.sign(
        sig_msg,
        _asym_padding.PSS(
            mgf=_asym_padding.MGF1(hashes.SHA256()),
            salt_length=32,
        ),
        hashes.SHA256(),
    )

    out = bytearray()
    out.append(VERSION_BYTE)
    out.extend(struct.pack("<I", state.epoch))
    out.extend(state.server_eph_pub)
    out.extend(struct.pack("<I", len(wrapped_aes)))
    out.extend(wrapped_aes)
    out.extend(struct.pack("<I", len(payload_blob)))
    out.extend(payload_blob)
    out.extend(sig)
    return bytes(out)


def decrypt_message_v2(raw: bytes, state: EpochState, agent_id: bytes) -> Optional[str]:
    if len(raw) < 1 + 4 + 32 + 8 + 32 + 28:
        return None
    if raw[0] != VERSION_BYTE:
        return None

    msg_epoch = struct.unpack_from("<I", raw, 1)[0]
    agent_eph_pub = raw[5:37]
    counter = struct.unpack_from("<Q", raw, 37)[0]
    chain_tag = raw[45:77]
    gcm_payload = raw[77:]

    if msg_epoch > state.epoch:
        rotate_epoch_server(state, agent_eph_pub, agent_id)
    elif msg_epoch + 1 < state.epoch:
        # Agent far behind — attempt with current state, will likely fail
        pass

    if not chain_verify(state, counter, gcm_payload, chain_tag):
        return None

    plaintext = _gcm_open(state.epoch_key, gcm_payload)
    if plaintext is None and state.prev_epoch_key:
        plaintext = _gcm_open(state.prev_epoch_key, gcm_payload)
    if plaintext is None:
        return None

    try:
        return plaintext.decode("utf-8", errors="replace")
    except Exception:
        return None


def encrypt_staging_v2(data: bytes, epoch_key: bytes) -> bytes:
    aes_key = os.urandom(32)
    wrapped_aes = _gcm_seal(epoch_key, aes_key)
    blob = _gcm_seal(aes_key, data)
    return struct.pack("<I", len(wrapped_aes)) + wrapped_aes + blob


def is_v2(raw: bytes) -> bool:
    return len(raw) > 0 and raw[0:1] == bytes([VERSION_BYTE])


def epoch_state_to_dict(state: EpochState) -> dict:
    return {
        "epoch": state.epoch,
        "epoch_key": state.epoch_key.hex(),
        "chain_key": state.chain_key.hex(),
        "counter": state.counter,
        "server_eph_priv": state.server_eph_priv.hex(),
        "server_eph_pub": state.server_eph_pub.hex(),
        "agent_eph_pub": state.agent_eph_pub.hex(),
        "prev_epoch_key": state.prev_epoch_key.hex() if state.prev_epoch_key else "",
    }


def epoch_state_from_dict(d: dict) -> EpochState:
    prev = d.get("prev_epoch_key", "")
    return EpochState(
        epoch=d["epoch"],
        epoch_key=bytes.fromhex(d["epoch_key"]),
        chain_key=bytes.fromhex(d["chain_key"]),
        counter=d["counter"],
        server_eph_priv=bytes.fromhex(d["server_eph_priv"]),
        server_eph_pub=bytes.fromhex(d["server_eph_pub"]),
        agent_eph_pub=bytes.fromhex(d["agent_eph_pub"]),
        prev_epoch_key=bytes.fromhex(prev) if prev else None,
    )
