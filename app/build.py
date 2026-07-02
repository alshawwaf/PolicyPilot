"""Build identity — surfaced in ``/version`` and the "About PolicyPilot" menu so ops can confirm exactly
which commit is running (ends the "did my redeploy take effect?" guessing).

The short SHA comes from the ``PILOT_BUILD_SHA`` env, set by the Dockerfile's ``GIT_SHA`` build-arg (pass the
commit at build). The build TIMESTAMP is baked into the image at build time (``app/_built_at.txt``) and needs
no configuration — it changes on every image rebuild, so even without a SHA you can tell a fresh deploy from
a stale one. Both degrade gracefully in dev (SHA "dev", empty timestamp)."""
from __future__ import annotations

import os
from pathlib import Path


def build_sha() -> str:
    """The deployed commit's short SHA (from PILOT_BUILD_SHA), or "dev" when unset (local / no build-arg)."""
    return (os.getenv("PILOT_BUILD_SHA") or "").strip() or "dev"


def built_at() -> str:
    """The image build timestamp baked at ``docker build`` (ISO-8601 UTC), or "" if not baked (dev)."""
    try:
        return Path(__file__).with_name("_built_at.txt").read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def build_info() -> dict:
    from . import __version__
    return {"version": __version__, "build": build_sha(), "built_at": built_at()}
