"""Encrypted-at-rest storage for a Management Server's login password or API key.

AES-256-GCM via :mod:`app.services.crypto` (org policy), in its own context so a token can't be
decrypted as a gateway/datacenter secret. Optional at runtime: if the crypto lib or a secret is
missing, :func:`available` is False, nothing is stored, and the caller must supply the secret per
call. The app boots either way.
"""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ManagementSecret, ManagementServer
from . import crypto

_log = logging.getLogger("dcsim.creds")

_INFO = b"dcsim-mgmt-secret-v1"   # HKDF context label — distinct from gateway/datacenter secrets


def available() -> bool:
    """True when a secret can actually be encrypted and stored (lib present + secret configured)."""
    return crypto.available()


def encrypt(plaintext: str) -> str:
    return crypto.encrypt(plaintext, _INFO)


def decrypt(token: str) -> str | None:
    return crypto.decrypt(token, _INFO)


def _row(db: Session, server: ManagementServer) -> ManagementSecret | None:
    return db.scalar(select(ManagementSecret).where(ManagementSecret.server_id == server.id))


def has_secret(db: Session, server: ManagementServer) -> bool:
    """A usable (decryptable) password/API key is on file. False if crypto is unavailable, since a
    stored secret couldn't be used then anyway."""
    if not available():
        return False
    row = _row(db, server)
    return bool(row and row.ciphertext)


def secret_kind(db: Session, server: ManagementServer) -> str | None:
    row = _row(db, server)
    return row.kind if (row and row.ciphertext) else None


def get_secret(db: Session, server: ManagementServer) -> str | None:
    """Decrypt and return the saved password/API key, or None if none stored / undecryptable."""
    row = _row(db, server)
    if not (row and row.ciphertext):
        return None
    plain = decrypt(row.ciphertext)
    if plain is None and available():     # key present but ciphertext won't open -> rotation/corruption
        _log.warning("management-server credential for id=%s did not decrypt (encryption key changed?) — "
                     "re-enter it on the server's Edit page", server.id)
    return plain


def store_secret(db: Session, server: ManagementServer, plaintext: str, kind: str = "password") -> None:
    """Encrypt and upsert the secret. Caller ensures `plaintext` is non-empty and `available()` is
    True (otherwise crypto.encrypt raises)."""
    token = encrypt(plaintext)
    row = _row(db, server)
    if row:
        row.ciphertext, row.kind = token, kind
    else:
        db.add(ManagementSecret(server_id=server.id, ciphertext=token, kind=kind))
    db.commit()


def clear_secret(db: Session, server: ManagementServer) -> None:
    row = _row(db, server)
    if row:
        db.delete(row)
        db.commit()
