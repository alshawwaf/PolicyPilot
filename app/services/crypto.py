"""Generic AES-256-GCM encryption-at-rest (org policy: credentials at rest use AES-256+).

The 32-byte key is derived from the app secret (``DCSIM_ENCRYPTION_KEY`` else the session secret) via
HKDF-SHA256. The ``info`` label gives **context separation** — gateway passwords and datacenter
credentials derive different keys from the same secret, so a token from one context can't be decrypted
in another. The ``cryptography`` lib is present in the deployed image but optional at runtime: if it's
missing or no secret is set, :func:`available` is False and callers fall back to a one-way hash.
"""
from __future__ import annotations

import base64
import os

from ..config import get_settings

try:  # present in the deployed image; absent in some minimal local envs
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    _CRYPTO = True
except Exception:  # pragma: no cover - exercised only where the lib is missing
    _CRYPTO = False

_PREFIX = "v1."  # token version, so the scheme can evolve without ambiguity


def _key(info: bytes) -> bytes | None:
    """Derive the 32-byte AES-256 key for a context, or None if crypto/secret is unavailable.

    Derived fresh each call (HKDF is cheap) so a config change is picked up without a restart.
    """
    if not _CRYPTO:
        return None
    s = get_settings()
    base = (s.encryption_key or s.session_secret or "").encode()
    if not base:
        return None
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(base)


def available() -> bool:
    """True when values can actually be encrypted (lib present + a secret configured)."""
    return _key(b"dcsim-probe") is not None


def encrypt(plaintext: str, info: bytes) -> str:
    key = _key(info)
    if key is None:
        raise RuntimeError("encryption unavailable")
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return _PREFIX + base64.urlsafe_b64encode(nonce + ct).decode()


def decrypt(token: str, info: bytes) -> str | None:
    key = _key(info)
    if key is None or not token or not token.startswith(_PREFIX):
        return None
    try:
        raw = base64.urlsafe_b64decode(token[len(_PREFIX):].encode())
        return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode()
    except Exception:
        return None
