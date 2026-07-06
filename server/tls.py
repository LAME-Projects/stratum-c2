"""
server/tls.py — Self-signed TLS certificate generation.

Generates a 2048-bit RSA cert valid for 10 years and returns its SHA-256
fingerprint for browser-side verification on first connect.
"""

from __future__ import annotations

import ipaddress
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def ensure_cert(cert_path: str, key_path: str) -> str:
    """Generate self-signed cert if missing. Returns SHA-256 fingerprint."""
    cert_p = Path(cert_path)
    key_p  = Path(key_path)

    if cert_p.exists() and key_p.exists():
        return fingerprint(cert_path)

    cert_p.parent.mkdir(parents=True, exist_ok=True)
    key_p.parent.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_p.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    key_p.chmod(0o600)

    hostname = socket.gethostname()
    subject  = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    san = x509.SubjectAlternativeName([
        x509.DNSName("localhost"),
        x509.DNSName(hostname),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return fingerprint(cert_path)


def fingerprint(cert_path: str) -> str:
    """Return colon-separated SHA-256 fingerprint of an existing PEM cert."""
    from cryptography.x509 import load_pem_x509_certificate
    data = Path(cert_path).read_bytes()
    cert = load_pem_x509_certificate(data)
    fp   = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in fp)
