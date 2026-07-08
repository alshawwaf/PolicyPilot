"""Gateway TLS helper: fetch a gateway's certificate so the SE can review its fingerprint and
pin it (trust-on-first-use), without ever disabling TLS verification on the actual apply.

This is the policy-safe alternative to a "skip TLS verify" toggle: we retrieve the presented
certificate once for review, then the apply (in apply_runner) verifies against that pinned PEM.
"""
import hashlib
import ssl


def cert_fingerprint(pem: str) -> str:
    """The colon-grouped SHA-256 fingerprint of a PEM certificate (for review/display)."""
    der = ssl.PEM_cert_to_DER_cert(pem)
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


def fetch_gateway_cert(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    """Retrieve the gateway's leaf certificate (PEM) and its SHA-256 fingerprint for review."""
    pem = ssl.get_server_certificate((host, port), timeout=timeout)
    return {"pem": pem.strip(), "fingerprint": cert_fingerprint(pem)}


def connect_error_message(host, port, exc) -> str:
    """An honest message for a failed connection to a management server.

    Distinguishes a *network* failure (unreachable / timed out — the portal
    couldn't open the socket) from a *TLS/certificate* failure (the handshake
    reached the server but the cert wasn't trusted). Only the latter mentions
    trusting the cert — a timeout must never be blamed on the pinned cert /
    auto-trust, which is what made an unreachable SMS read as a "trust" problem.
    """
    cause = getattr(exc, "__cause__", None)
    text = f"{exc}".lower()
    is_tls = isinstance(exc, ssl.SSLError) or isinstance(cause, ssl.SSLError) or any(
        k in text for k in ("certificate", "ssl", "tls handshake", "cert verify",
                             "self-signed", "self signed", "verify failed"))
    if is_tls:
        return (f"TLS/certificate error connecting to {host}:{port} — {exc}. If this is a self-signed "
                f"Check Point certificate, tick “Trust this server's certificate” on the server "
                f"profile (or paste/pin the certificate), then try again.")
    is_timeout = "timed out" in text or "timeout" in text or exc.__class__.__name__.endswith("Timeout")
    if is_timeout:
        return (f"Could not reach {host}:{port} — the connection timed out. The management server is "
                f"not reachable from the portal. Check the host and port, and any firewall / VPN / routing "
                f"between the portal and the server. (This is a network-path issue, not a certificate/"
                f"trust issue.)")
    return (f"Could not reach {host}:{port} — {exc}. Check the host and port, and that the management "
            f"server is reachable from the portal (network / firewall).")


def ensure_pinned(db, gw) -> bool:
    """Trust-on-first-use: if the gateway opts into auto-trust and has no cert pinned yet, fetch the
    cert it currently presents and pin it to the profile. The apply/fetch that follows then verifies
    against this pinned PEM — TLS verification is never disabled, we just decide what to trust.

    Best-effort: if the gateway is unreachable right now we leave the cert empty and try again on the
    next connect. Returns True when a cert was newly pinned. Safe to call on every connect — once a
    cert is present it's a no-op.
    """
    if not getattr(gw, "auto_trust", False) or (gw.cert_pem or "").strip():
        return False
    try:
        pem = fetch_gateway_cert(gw.host, gw.port).get("pem", "").strip()
    except Exception:
        return False
    if not pem:
        return False
    gw.cert_pem = pem
    db.commit()
    return True


def pin_now(db, gw) -> tuple[bool, str]:
    """Eagerly establish trust AT SAVE TIME: if the profile opts into auto-trust and has no cert pinned
    yet, fetch the certificate it currently presents and pin it now (server-side) — so the first
    apply/fetch verifies against an already-pinned cert instead of relying on a lazy first-connect that
    can error if the gateway blips. Returns (pinned_now, fingerprint). Best-effort: if the gateway isn't
    reachable right now it returns (False, "") and the lazy ensure_pinned still covers the next connect."""
    if ensure_pinned(db, gw):
        return True, cert_fingerprint(gw.cert_pem)
    return False, ""
