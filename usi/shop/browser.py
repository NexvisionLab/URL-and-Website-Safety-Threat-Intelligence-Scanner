"""Renders a shop page in a real browser (headless Chromium via Playwright).

Used when the plain fetch can't read the page - shops built entirely by
JavaScript - and to see the page as a phone visitor arriving from a
Facebook advert, which is who some fake-shop campaigns show their
storefront to while everyone else gets an error page.

Invariants, the same as the rest of the tool:
- Look, never act: no clicks, no typing, no form submission, downloads
  refused. The page's own scripts run, as in any browser.
- No evasion: the browser identifies as headless Chrome (the phone view
  uses a phone's user agent, which is what the check is about), no
  fingerprint masking, no challenge solving. A shop behind an interactive
  bot check stays unexamined.
- Every request the page makes - including those its scripts start - is
  checked, and one aimed at a non-public address is refused. Images,
  media and fonts are not loaded.
- A fresh browser per render: nothing carries over between shops.

Playwright is an optional dependency (requirements-render.txt); without
it this module reports itself unavailable and nothing else changes."""
import importlib.util
import ipaddress
import os
import socket
import time
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

PROFILES = ("desktop", "phone_facebook")
FACEBOOK_REFERER = "https://m.facebook.com/"
PHONE_DEVICE = "Pixel 7"
NAV_TIMEOUT_MS = 20_000
SETTLE_MS = 6_000
MAX_HTML_CHARS = 2_000_000
_SKIPPED_RESOURCES = {"image", "media", "font"}


@dataclass
class Rendered:
    ok: bool
    profile: str
    status: "int | None" = None
    final_url: "str | None" = None
    title: "str | None" = None
    html: str = ""
    error: "str | None" = None
    blocked_requests: int = 0
    seconds: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


def available() -> bool:
    return importlib.util.find_spec("playwright") is not None


def _is_public(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not ip.is_multicast


class AddressGuard:
    """Decides, per host, whether the browser may contact it. Always on here - unlike the
    requests-based guard - because a page's own scripts choose where these requests go."""

    def __init__(self, resolver=socket.getaddrinfo):
        self._resolver = resolver
        self._cache: "dict[str, bool]" = {}

    def allowed(self, url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme in ("data", "blob", "about"):
            return True
        if parsed.scheme not in ("http", "https", "ws", "wss"):
            return False
        host = (parsed.hostname or "").strip("[]").rstrip(".").lower()
        if not host:
            return False
        if host not in self._cache:
            try:
                infos = self._resolver(host, None, type=socket.SOCK_STREAM)
                self._cache[host] = bool(infos) and all(_is_public(i[4][0]) for i in infos)
            except (socket.gaierror, UnicodeError, OSError, ValueError):
                self._cache[host] = False
        return self._cache[host]


def render(url: str, profile: str = "desktop", executable_path: "str | None" = None,
           guard: "AddressGuard | None" = None) -> Rendered:
    if profile not in PROFILES:
        raise ValueError(f"unknown profile {profile!r}")
    started = time.monotonic()
    guard = guard or AddressGuard()
    if not guard.allowed(url):
        return Rendered(ok=False, profile=profile, error="this address cannot be checked")
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return Rendered(ok=False, profile=profile, error="the browser is not installed")

    blocked = 0

    def route(r):
        nonlocal blocked
        if r.request.resource_type in _SKIPPED_RESOURCES:
            return r.abort()
        if not guard.allowed(r.request.url):
            blocked += 1
            return r.abort()
        return r.continue_()

    result = Rendered(ok=False, profile=profile)
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True,
                                         executable_path=executable_path or os.environ.get("USI_CHROMIUM_PATH") or None)
            try:
                options = {"accept_downloads": False, "java_script_enabled": True}
                if profile == "phone_facebook":
                    options.update(pw.devices[PHONE_DEVICE])
                context = browser.new_context(**options)
                context.route("**/*", route)
                if hasattr(context, "route_web_socket"):  # WebSockets bypass context.route
                    def ws_route(ws):
                        nonlocal blocked
                        # Not calling connect_to_server() leaves the socket talking to Playwright's mock:
                        # nothing leaves the browser. (Closing it from here deadlocks the sync API.)
                        if guard.allowed(ws.url):
                            ws.connect_to_server()
                        else:
                            blocked += 1
                    context.route_web_socket("**/*", ws_route)
                page = context.new_page()
                page.on("dialog", lambda d: d.dismiss())
                response = page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS,
                                     referer=FACEBOOK_REFERER if profile == "phone_facebook" else None)
                try:
                    page.wait_for_load_state("networkidle", timeout=SETTLE_MS)
                except PlaywrightError:
                    pass  # pages that never go quiet are read as they are
                if not guard.allowed(page.url):
                    raise RuntimeError("the page moved to an address that cannot be checked")
                result = Rendered(
                    ok=True, profile=profile,
                    status=response.status if response else None,
                    final_url=page.url, title=page.title()[:300],
                    html=page.content()[:MAX_HTML_CHARS],
                )
            finally:
                browser.close()
    except Exception as e:  # noqa: BLE001 - a failed render is reported, never raised into the check
        result = Rendered(ok=False, profile=profile, error=f"{type(e).__name__}: {str(e).splitlines()[0][:160]}")
    result.blocked_requests = blocked
    result.seconds = round(time.monotonic() - started, 1)
    return result
