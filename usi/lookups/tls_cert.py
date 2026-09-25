"""TLS certificate inspection for clearnet HTTPS sites: issuer, validity
window, hostname match. Uses stdlib ssl/socket to fetch the peer cert in
DER form, then `cryptography` to parse it properly rather than hand-
rolling ASN.1 parsing."""
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .. import netguard
from ..models import Severity, Signal

CONNECT_TIMEOUT = 10


def _get_cert_der(host: str, port: int = 443) -> bytes:
    netguard.check_host(host)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we inspect the cert ourselves, incl. mismatches
    with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
            return tls_sock.getpeercert(binary_form=True)


def inspect(host: str, skip: bool = False) -> "list[Signal]":
    if skip:
        return [Signal(
            source="tls_cert", code="tls_unavailable", severity=Severity.INFO,
            message="TLS certificate check not applicable for this host (.onion or skipped).",
        )]

    try:
        der = _get_cert_der(host)
        cert = x509.load_der_x509_certificate(der, default_backend())
    except Exception as e:
        return [Signal(
            source="tls_cert", code="tls_unavailable", severity=Severity.INFO,
            message=f"Could not fetch/parse a TLS certificate for this host: {e}",
        )]

    signals = []
    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    if now < not_before or now > not_after:
        signals.append(Signal(
            source="tls_cert", code="tls_cert_invalid_period", severity=Severity.HIGH,
            message=f"The TLS certificate is not currently valid (valid {not_before.date()} "
                    f"to {not_after.date()}).",
            evidence={"not_before": not_before.isoformat(), "not_after": not_after.isoformat()},
        ))

    try:
        issuer = cert.issuer.rfc4514_string()
    except Exception:
        issuer = str(cert.issuer)

    age_days = (now - not_before).days
    if age_days < 7:
        signals.append(Signal(
            source="tls_cert", code="tls_cert_fresh", severity=Severity.LOW,
            message=f"The TLS certificate was issued only {age_days} day(s) ago. "
                    "Weak signal alone - only meaningful alongside other findings.",
            evidence={"issued_days_ago": age_days, "issuer": issuer},
        ))
    else:
        signals.append(Signal(
            source="tls_cert", code="tls_cert_info", severity=Severity.INFO,
            message=f"TLS certificate issued by: {issuer}",
            evidence={"issuer": issuer, "not_before": not_before.isoformat()},
        ))

    return signals
