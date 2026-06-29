"""Encrypted-at-rest storage for the optional saved gateway password.

AES-256-GCM via :mod:`app.services.crypto` (org policy). Optional at runtime: if the crypto lib or a
secret is missing, :func:`available` is False, nothing is stored, and callers fall back to the
per-apply password field. The app always boots either way.
"""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Gateway, GatewaySecret
from . import crypto

_log = logging.getLogger("dcsim.creds")

# HKDF context label — unchanged, so gateway secrets stored before the crypto refactor still decrypt.
_INFO = b"dcsim-gateway-password-v1"


def available() -> bool:
    """True when a password can actually be encrypted and stored (lib present + secret set)."""
    return crypto.available()


def encrypt(plaintext: str) -> str:
    return crypto.encrypt(plaintext, _INFO)


def decrypt(token: str) -> str | None:
    return crypto.decrypt(token, _INFO)


# --- DB helpers -------------------------------------------------------------------------

def _row(db: Session, gw: Gateway) -> GatewaySecret | None:
    return db.scalar(select(GatewaySecret).where(GatewaySecret.gateway_id == gw.id))


def has_password(db: Session, gw: Gateway) -> bool:
    """A usable (decryptable) password is on file for this gateway. Returns False if the
    encryption key/library is unavailable, since a stored secret can't be used then anyway."""
    if not available():
        return False
    row = _row(db, gw)
    return bool(row and row.ciphertext)


def get_password(db: Session, gw: Gateway) -> str | None:
    """Decrypt and return the saved password, or None if none is stored / cannot be decrypted."""
    row = _row(db, gw)
    if not (row and row.ciphertext):
        return None
    plain = decrypt(row.ciphertext)
    if plain is None and available():     # key present but ciphertext won't open -> rotation/corruption
        _log.warning("gateway credential for id=%s did not decrypt (encryption key changed?) — "
                     "re-enter it on the gateway's Edit page", gw.id)
    return plain


def store_password(db: Session, gw: Gateway, plaintext: str) -> None:
    """Encrypt and upsert the password. Caller ensures `plaintext` is non-empty and that
    `available()` is True (otherwise this raises)."""
    token = encrypt(plaintext)
    row = _row(db, gw)
    if row:
        row.ciphertext = token
    else:
        db.add(GatewaySecret(gateway_id=gw.id, ciphertext=token))


def clear_password(db: Session, gw: Gateway) -> None:
    """Remove any saved password for this gateway."""
    row = _row(db, gw)
    if row:
        db.delete(row)
