from __future__ import annotations

import base64
import time
import uuid
from dataclasses import dataclass
from typing import Dict, List, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def _b64url_uint(n: int) -> str:
    # base64url-encode an unsigned big-endian integer (no padding)
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


@dataclass
class RSAKey:
    kid: str
    private_pem: bytes
    public_pem: bytes
    n_b64: str
    e_b64: str
    exp_ts: int  # unix epoch seconds

    @property
    def is_expired(self) -> bool:
        return int(time.time()) >= self.exp_ts


class KeyStore:
    """
    Very small in-memory keystore:
      - exactly one active key ("current")
      - one expired key (for grading the 'expired' path)
    In a real app you would persist keys and rotate them on a schedule.
    """

    def __init__(self) -> None:
        now = int(time.time())

        # Create ACTIVE key that expires in ~24h
        self.current = self._generate_key(exp_ts=now + 24 * 3600)

        # Create EXPIRED key that expired 1h ago
        self.expired = self._generate_key(exp_ts=now - 3600)

    def _generate_key(self, exp_ts: int) -> RSAKey:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_pem = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        pubnum = key.public_key().public_numbers()
        n_b64 = _b64url_uint(pubnum.n)
        e_b64 = _b64url_uint(pubnum.e)

        return RSAKey(
            kid=str(uuid.uuid4()),
            private_pem=private_pem,
            public_pem=public_pem,
            n_b64=n_b64,
            e_b64=e_b64,
            exp_ts=exp_ts,
        )

    def jwks(self) -> Dict[str, List[Dict[str, str]]]:
        """
        Return JWKS with ONLY unexpired keys.
        """
        keys = []
        if not self.current.is_expired:
            keys.append({
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": self.current.kid,
                "n": self.current.n_b64,
                "e": self.current.e_b64,
            })
        # DO NOT include expired key(s) here.
        return {"keys": keys}

    def select_key(self, want_expired: bool) -> Tuple[RSAKey, int]:
        """
        Returns (key, jwt_exp).
        If want_expired=True → use the expired key AND put exp in the past.
        Otherwise → use current key and give a short future exp.
        """
        now = int(time.time())
        if want_expired:
            key = self.expired
            jwt_exp = now - 60  # already expired
        else:
            key = self.current
            jwt_exp = now + 5 * 60  # 5 minutes
        return key, jwt_exp
