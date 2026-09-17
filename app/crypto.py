"""Ed25519 signing of signed tree heads (STHs).

Each tenant has an ordered key history.  The key that signs a given tree
head is identified by ``key_id`` in the STH response; old keys are retained
so signatures made before a rotation remain verifiable forever.
"""

from __future__ import annotations

import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Domain-separated prefix for the signed blob (avoids cross-protocol reuse).
STH_SIGNATURE_PREFIX = b"transparent-log-v1/sth-signature\n"


def generate_keypair() -> tuple[str, str]:
    """Return (private_key_pem, public_key_pem), both PKCS8/SPKI PEM strings."""
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return priv_pem, pub_pem


def public_key_pem(private_key_pem: str) -> str:
    priv = load_private_key(private_key_pem)
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def load_private_key(pem: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("not an Ed25519 private key")
    return key


def load_public_key(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("not an Ed25519 public key")
    return key


def sth_signing_input(tree_id: str, tree_size: int, timestamp_ms: int,
                      root_hash: bytes, epoch: int) -> bytes:
    """Deterministic byte string covered by the STH signature."""
    return (
        STH_SIGNATURE_PREFIX
        + f"tree_id={tree_id}\n"
          f"tree_size={tree_size}\n"
          f"timestamp={timestamp_ms}\n"
          f"sha256_root_hash={base64.b64encode(root_hash).decode('ascii')}\n"
          f"epoch={epoch}\n".encode("ascii")
    )


def sign_sth(private_key_pem: str, signing_input: bytes) -> bytes:
    return load_private_key(private_key_pem).sign(signing_input)


def verify_sth(public_key_pem: str, signing_input: bytes, signature: bytes) -> bool:
    try:
        load_public_key(public_key_pem).verify(signature, signing_input)
        return True
    except (InvalidSignature, ValueError):
        return False
