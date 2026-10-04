"""Optional guard that stops the tool reaching internal addresses.

The tool follows redirects, fetches favicons a page declares, and opens TLS
connections to whatever host it is given. Run as a command-line tool on your own
machine that is what you want. Run behind a public web form it is a server-side
request forgery hole: someone submits http://169.254.169.254/ or a redirect to
http://127.0.0.1:9200/ and the tool reports what answered.

Set USI_BLOCK_PRIVATE_ADDRESSES=1 to refuse any target whose name resolves to a
loopback, private, link-local, reserved or otherwise non-global address. The check
runs before every request, including each redirect hop. Requests sent through a Tor
proxy are not checked here because the proxy, not this machine, resolves the name.

Names the system resolver maps to private addresses (2026-10-04). Some VPN and
"smart DNS" resolvers answer for region-restricted sites (bbc.com, itv.com,
disneyplus.com ...) with a private address in their own range, so a perfectly
public site looked internal and was refused. For a real DNS name whose system answer
is not public, the guard now asks public resolvers directly (PUBLIC_RESOLVERS, over
UDP). If every address they return is public, the connection is made to THAT address
(the host name is still used for the Host header, the TLS server name and the
certificate check), so the private answer is never connected to. If they return
nothing, or anything non-public, the target stays refused. IP literals, `localhost`
and numeric shorthand such as 2130706433 never take this path.

Known limit: when the system answer is public the name is resolved once here and
again when the connection is made, so a DNS server that changes its answer between
the two can still get through. Run the service on a network with no route to
internal hosts as well.
"""
import ipaddress
import os
import random
import socket
import struct
import threading
from urllib.parse import urlsplit

import requests
import urllib3.util.connection as _urllib3_connection
from requests.adapters import HTTPAdapter

ENV_VAR = "USI_BLOCK_PRIVATE_ADDRESSES"

# Resolvers asked directly when the system resolver gives a non-public answer for a DNS name.
PUBLIC_RESOLVERS = ("1.1.1.1", "9.9.9.9")
DNS_TIMEOUT = 2.0


class BlockedAddressError(requests.RequestException):
    """The target resolves to an address this tool has been told not to reach."""


def enabled() -> bool:
    return os.environ.get(ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def _looks_like_dns_name(host: str) -> bool:
    """A dotted name with letters in its last label: never an IP literal, `localhost`,
    or numeric shorthand (2130706433, 0x7f.0.0.1), which must stay blocked."""
    labels = host.split(".")
    if len(labels) < 2 or not any(c.isalpha() for c in labels[-1]):
        return False
    return all(0 < len(label) <= 63 and all(c.isalnum() or c == "-" for c in label) for label in labels)


# --- a minimal DNS "A" lookup against a chosen resolver (stdlib only) -------------------------

def _build_query(name: str, query_id: int) -> bytes:
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"
    return struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + question + struct.pack(">HH", 1, 1)


def _skip_name(data: bytes, pos: int) -> int:
    while True:
        if pos >= len(data):
            raise ValueError("truncated name")
        length = data[pos]
        if length == 0:
            return pos + 1
        if length >= 0xC0:                       # compression pointer: two bytes, ends the name
            return pos + 2
        pos += 1 + length


def _parse_a_records(data: bytes, query_id: int) -> "list[str]":
    """The IPv4 addresses in a DNS response, or [] for an error/other-id/empty answer.
    Raises ValueError for a malformed packet."""
    if len(data) < 12:
        raise ValueError("short packet")
    rid, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if rid != query_id or not flags & 0x8000 or flags & 0x000F:      # not our response, or an error rcode
        return []
    pos = 12
    for _ in range(qdcount):
        pos = _skip_name(data, pos) + 4
    found = []
    for _ in range(ancount):
        pos = _skip_name(data, pos)
        if pos + 10 > len(data):
            raise ValueError("truncated record")
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        if pos + rdlen > len(data):
            raise ValueError("truncated rdata")
        if rtype == 1 and rdlen == 4:
            found.append(socket.inet_ntoa(data[pos:pos + 4]))
        pos += rdlen
    return found


def _query_a(resolver: str, name: str) -> "list[str]":
    """IPv4 addresses `resolver` gives for `name`; [] when it has none or does not answer."""
    query_id = random.getrandbits(16)
    try:
        packet = _build_query(name, query_id)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(DNS_TIMEOUT)
            sock.sendto(packet, (resolver, 53))
            data, source = sock.recvfrom(2048)
        if source[0] != resolver:
            return []
        return _parse_a_records(data, query_id)
    except (OSError, ValueError, UnicodeError):
        return []


def _public_dns_pin(name: str) -> "str | None":
    """An address to connect to for `name` from the public resolvers, or None to refuse.
    Every address any resolver returns must be public, and at least one must answer."""
    addresses = []
    for resolver in PUBLIC_RESOLVERS:
        for address in _query_a(resolver, name):
            if not _is_public(address):
                return None
            addresses.append(address)
    return addresses[0] if addresses else None


# --- the check --------------------------------------------------------------------------------

def vet_host(host: "str | None") -> "str | None":
    """Raises BlockedAddressError if `host` is, or resolves to, a non-public address.
    Returns None when the system resolver's answer is fine to use, or an address (from the
    public resolvers) to connect to instead when the system answer was not public.
    A name that does not resolve at all is let through: the request that follows fails
    on its own, and there is nothing internal to reach."""
    if not enabled():
        return None
    if not host:
        raise BlockedAddressError("the target has no host name")
    host = host.strip("[]").rstrip(".")
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return None
    if all(_is_public(info[4][0]) for info in infos):
        return None
    if _looks_like_dns_name(host):
        pin = _public_dns_pin(host)
        if pin:
            return pin
    raise BlockedAddressError(f"{host} resolves to a non-public address, which this service does not contact")


def check_host(host: "str | None") -> None:
    """vet_host without the address: raises BlockedAddressError, otherwise returns."""
    vet_host(host)


def create_connection(host: str, port: int, timeout: float):
    """socket.create_connection that vets `host` first and connects to the vetted address."""
    pin = vet_host(host)
    return socket.create_connection((pin or host, port), timeout=timeout)


# --- HTTP: connect to the vetted address, keep the host name for Host/SNI/certificate ------------

_local = threading.local()
_original_create_connection = _urllib3_connection.create_connection


def _create_connection(address, *args, **kwargs):
    pins = getattr(_local, "pins", None)
    if pins and address[0] in pins:
        address = (pins[address[0]], address[1])
    return _original_create_connection(address, *args, **kwargs)


_urllib3_connection.create_connection = _create_connection


class GuardedAdapter(HTTPAdapter):
    """Runs the vetting before every request, so each redirect hop is checked too. When the
    system resolver's answer for the host was not public, the connection goes to the address
    the public resolvers gave instead; the URL, Host header, TLS server name and certificate
    check are unchanged."""

    def send(self, request, **kwargs):
        host = (urlsplit(request.url).hostname or "").lower()
        pin = vet_host(host)
        if pin is None:
            return super().send(request, **kwargs)
        previous = getattr(_local, "pins", None)
        _local.pins = {host: pin}
        try:
            return super().send(request, **kwargs)
        finally:
            _local.pins = previous
