from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


@dataclass
class Ed25519Signer:
    """Sign and verify arbitrary bytes with Ed25519."""

    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> Ed25519Signer:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> Ed25519Signer:
        return cls(Ed25519PrivateKey.from_private_bytes(raw))

    @classmethod
    def from_pem_file(cls, path: Path) -> Ed25519Signer:
        data = path.read_bytes()
        key = serialization.load_pem_private_key(data, password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("PEM must be an Ed25519 private key")
        return cls(key)

    def public_bytes(self) -> bytes:
        pub = self.private_key.public_key()
        return pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> bytes:
        return self.private_key.sign(message)

    def sign_b64(self, message: bytes) -> str:
        return base64.b64encode(self.sign(message)).decode("ascii")

    def write_pem_file(self, path: Path) -> None:
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path.write_bytes(pem)

    def verify_b64(self, message: bytes, signature_b64: str, public_key_raw: bytes | None = None) -> bool:
        try:
            sig = base64.b64decode(signature_b64.encode("ascii"), validate=True)
        except Exception:
            return False
        if public_key_raw is None:
            pub = self.private_key.public_key()
        else:
            pub = Ed25519PublicKey.from_public_bytes(public_key_raw)
        try:
            pub.verify(sig, message)
        except Exception:
            return False
        return True
