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

Known limit: the name is resolved once here and again when the connection is made,
so a DNS server that changes its answer between the two can still get through. Run
the service on a network with no route to internal hosts as well.
"""
import ipaddress
import os
import socket

import requests
from requests.adapters import HTTPAdapter

ENV_VAR = "USI_BLOCK_PRIVATE_ADDRESSES"


class BlockedAddressError(requests.RequestException):
    """The target resolves to an address this tool has been told not to reach."""


def enabled() -> bool:
    return os.environ.get(ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


def check_host(host: "str | None") -> None:
    """Raises BlockedAddressError if `host` is, or resolves to, a non-public address.
    A name that does not resolve at all is let through: the request that follows fails
    on its own, and there is nothing internal to reach."""
    if not enabled():
        return
    if not host:
        raise BlockedAddressError("the target has no host name")
    host = host.strip("[]").rstrip(".")
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return
    for info in infos:
        if not _is_public(info[4][0]):
            raise BlockedAddressError(f"{host} resolves to a non-public address, which this service does not contact")


class GuardedAdapter(HTTPAdapter):
    """Runs check_host before every request, so each redirect hop is checked too."""

    def send(self, request, **kwargs):
        from urllib.parse import urlsplit

        check_host(urlsplit(request.url).hostname)
        return super().send(request, **kwargs)
