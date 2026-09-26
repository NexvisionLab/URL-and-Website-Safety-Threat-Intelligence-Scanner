"""Where rendered pages come from, and what comparing two views shows.

A renderer is chosen by configuration:
- USI_RENDER_URL=http://127.0.0.1:8796 - a separate render service (DarkNyx
  runs the browser in its own sandboxed process; see browser.py);
- USI_RENDER_LOCAL=1 - a browser in this process (command-line use,
  needs `pip install -r requirements-render.txt` and `playwright install chromium`);
- neither - no rendering; the analyzer works exactly as without it.

compare_views() looks at the same shop as a desktop visitor and as a phone
visitor arriving from a Facebook link. Some fake-shop campaigns show their
storefront only to the second and an error or empty page to everyone else,
so that reviewers and security scanners never see it."""
import os
from urllib.parse import urlparse

import requests

from ..lookups.rdap import registrable_domain
from ..models import Severity, Signal
from . import browser, pages

SOURCE = "shop_copy"
RENDER_TIMEOUT = 45


class RemoteRenderer:
    def __init__(self, base_url: str, timeout: int = RENDER_TIMEOUT):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def render(self, url: str, profile: str) -> browser.Rendered:
        try:
            resp = requests.post(f"{self.base_url}/render", json={"url": url, "profile": profile}, timeout=self.timeout)
            data = resp.json() if resp.status_code == 200 else None
        except (requests.RequestException, ValueError):
            data = None
        if not isinstance(data, dict):
            return browser.Rendered(ok=False, profile=profile, error="the render service did not answer")
        fields = browser.Rendered.__dataclass_fields__
        return browser.Rendered(**{k: v for k, v in data.items() if k in fields})


class LocalRenderer:
    def __init__(self, executable_path: "str | None" = None):
        self.executable_path = executable_path

    def render(self, url: str, profile: str) -> browser.Rendered:
        return browser.render(url, profile, executable_path=self.executable_path)


def get_renderer():
    if os.environ.get("USI_RENDER_URL"):
        return RemoteRenderer(os.environ["USI_RENDER_URL"])
    if os.environ.get("USI_RENDER_LOCAL", "").strip().lower() in {"1", "true", "yes", "on"} and browser.available():
        return LocalRenderer()
    return None


def as_page(r: browser.Rendered) -> "pages.Page | None":
    """The rendered page if it is really the shop: loaded, 2xx, not a bot check."""
    if not r.ok or not r.html or not (r.status and 200 <= r.status < 300):
        return None
    page = pages.parse_page(r.final_url or "", r.html)
    return None if pages.is_challenge(page) else page


def _looks_empty(r: browser.Rendered) -> bool:
    """An error page or a blank page - but not a bot check, which says nothing about the shop."""
    if not r.ok:
        return False  # a failed render says nothing about what the shop shows
    page = pages.parse_page(r.final_url or "", r.html)
    if pages.is_challenge(page):
        return False
    if r.status and r.status >= 400:
        return True
    return len(page.text) < 200 and len(page.links) < 5


def compare_views(desktop: browser.Rendered, phone: browser.Rendered) -> "list[Signal]":
    phone_page = as_page(phone)
    if phone_page is None or not pages.is_readable(phone_page):
        return []
    evidence = {"desktop_status": desktop.status, "phone_status": phone.status,
                "desktop_title": (desktop.title or "")[:120], "phone_title": (phone.title or "")[:120]}
    if desktop.ok and pages.is_challenge(pages.parse_page(desktop.final_url or "", desktop.html)):
        return []  # the desktop view is a bot check: nothing to compare with
    if _looks_empty(desktop):
        return [Signal(
            source=SOURCE, code="shop_cloaked_for_ads", severity=Severity.HIGH,
            message=("The shop shows its storefront only to phone visitors arriving from Facebook; other visitors get "
                     "an error or an empty page. Fake-shop campaigns hide from reviewers and security scanners this way."),
            evidence=evidence,
        )]
    desktop_site = registrable_domain(urlparse(desktop.final_url or "").hostname or "")
    phone_site = registrable_domain(urlparse(phone.final_url or "").hostname or "")
    if desktop.ok and desktop_site and phone_site and desktop_site != phone_site:
        return [Signal(
            source=SOURCE, code="shop_redirects_ad_visitors", severity=Severity.MEDIUM,
            message=(f"Phone visitors arriving from Facebook are sent to a different website ({phone_site}) "
                     f"than other visitors ({desktop_site})."),
            evidence={**evidence, "desktop_site": desktop_site, "phone_site": phone_site},
        )]
    return [Signal(source=SOURCE, code="shop_views_consistent", severity=Severity.INFO,
                   message="The shop looks the same to a desktop visitor and to a phone visitor arriving from Facebook.")]
