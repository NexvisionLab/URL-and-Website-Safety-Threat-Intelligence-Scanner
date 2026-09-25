"""The shop's pages as the analyzer sees them, and the few extra
same-site requests it makes: linked contact / about / returns / terms
pages and the public product feeds Shopify and WooCommerce stores
publish.

Same invariants as content/fetcher.py: GET only, capped size and time,
the configured honest User-Agent, the internal-address guard (through
net.build_session), and never a form, a cart or a checkout."""
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urldefrag, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from ..lookups.rdap import registrable_domain
from ..net import build_session, capped_get

MAX_EXTRA_PAGES = 4
PAGE_TIMEOUT_SECONDS = 10
PAGE_MAX_BYTES = 1_000_000
JSON_MAX_BYTES = 3_000_000
TEXT_CAP = 300_000

# Which linked pages are worth reading, in the order they are picked.
# Matched against the link's text and its path, lowercased.
PAGE_KINDS = (
    ("contact", r"contact|kontakt|impressum|imprint|legal notice|mentions l[ée]gales|aviso legal|get in touch"
                r"|customer (?:service|care)|\bhelp\b|\bfaq\b|\bsupport\b|hilfe|kundenservice"),
    ("about", r"about|über uns|ueber-uns|who we are|our story|qui sommes"),
    ("refund", r"refund|return|retour|rückgabe|ruckgabe|widerruf|exchange|remboursement|devoluci"),
    ("terms", r"terms|conditions|\bagb\b|\bcgv\b|t&c|terminos|condiciones"),
    ("shipping", r"shipping|delivery|versand|livraison|env[ií]o"),
    ("privacy", r"privacy|datenschutz|confidentialit|privacidad"),
)
_KIND_RES = [(k, re.compile(p, re.I)) for k, p in PAGE_KINDS]
# Pages worth fetching: the ones that name who runs the shop and how it
# treats buyers. Privacy and shipping pages are only noted as present.
_FETCH_KINDS = ("contact", "about", "refund", "terms")


@dataclass
class Page:
    url: str
    html: str
    text: str
    title: "str | None" = None
    links: "list[tuple[str, str]]" = field(default_factory=list)  # (absolute url, link text)


# A bot-protection interstitial is not the shop: judging it would report
# "no contact details" for any shop behind Cloudflare, genuine or not.
_CHALLENGE_RE = re.compile(
    r"(?i)^(?:just a moment\.*|attention required!? \| cloudflare|access denied|security check|ddos-guard"
    r"|one moment, please\.*|please wait\.*|checking your browser.*)$")
_CHALLENGE_TEXT_RE = re.compile(
    r"(?i)enable javascript and cookies to continue|checking (?:if the site connection is secure|your browser)"
    r"|verify(?:ing)? you are (?:a )?human|sorry, you have been blocked")
READABLE_TEXT = 400
READABLE_LINKS = 15


def is_challenge(page: "Page") -> bool:
    if page.title and _CHALLENGE_RE.match(page.title.strip()):
        return True
    return len(page.text) < 3000 and bool(_CHALLENGE_TEXT_RE.search(page.text))


def is_readable(page: "Page") -> bool:
    """Enough server-rendered content to look for contact details and policies. Pages built
    entirely by JavaScript come back almost empty to a plain request; absence there proves nothing."""
    return len(page.text) >= READABLE_TEXT or len(page.links) >= READABLE_LINKS


def parse_page(url: str, html: str) -> Page:
    soup = BeautifulSoup(html or "", "lxml")
    links = []
    for a in soup.find_all("a", href=True):
        href = a.get("href") or ""
        if href.startswith(("javascript:", "#")):
            continue
        links.append((urldefrag(urljoin(url, href))[0], " ".join(a.get_text(" ").split())[:120]))
    title = soup.title.get_text(strip=True) if soup.title else None
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = " ".join(soup.get_text(separator=" ").split())[:TEXT_CAP]
    return Page(url=url, html=html or "", text=text, title=title, links=links)


def same_site(url: str, host: str) -> bool:
    link_host = (urlparse(url).hostname or "").lower()
    if not link_host:
        return False
    if link_host == host.lower():
        return True
    a, b = registrable_domain(link_host), registrable_domain(host)
    return bool(a) and a == b


def classify_links(page: Page, host: str) -> "dict[str, list[str]]":
    """Same-site links by kind (contact, refund, ...), in page order."""
    found: "dict[str, list[str]]" = {}
    for url, text in page.links:
        if not url.startswith(("http://", "https://")) or not same_site(url, host):
            continue
        path = urlparse(url).path.lower()
        haystack = f"{text.lower()} {path}"
        for kind, rx in _KIND_RES:
            if rx.search(haystack):
                bucket = found.setdefault(kind, [])
                if url not in bucket:
                    bucket.append(url)
                break
    return found


def pick_extra_pages(links_by_kind: "dict[str, list[str]]", main_url: str) -> "list[str]":
    """At most MAX_EXTRA_PAGES pages: the first link of each useful kind."""
    picked = []
    seen = {main_url.rstrip("/")}
    for kind in _FETCH_KINDS:
        for url in links_by_kind.get(kind, []):
            if url.rstrip("/") not in seen:
                picked.append(url)
                seen.add(url.rstrip("/"))
                break
        if len(picked) >= MAX_EXTRA_PAGES:
            break
    return picked


class Fetcher:
    """One requests session for all the analyzer's extra requests."""

    def __init__(self, user_agent: str, tor_proxy: "str | None" = None):
        self.session = build_session(user_agent, tor_proxy)

    def _get(self, url: str, max_bytes: int):
        return capped_get(self.session, url, timeout=PAGE_TIMEOUT_SECONDS, max_bytes=max_bytes,
                          total_timeout=PAGE_TIMEOUT_SECONDS * 1.5)

    def page(self, url: str) -> "Page | None":
        try:
            resp = self._get(url, PAGE_MAX_BYTES)
        except requests.RequestException:
            return None
        except Exception:  # noqa: BLE001 - an extra page is optional; never let it fail the check
            return None
        ctype = (resp.headers.get("content-type") or "").lower()
        if resp.status_code != 200 or ("html" not in ctype and "text/plain" not in ctype):
            return None
        html = resp._capped_content.decode(resp.encoding or "utf-8", errors="ignore")
        return parse_page(resp.url, html)

    def json(self, url: str):
        try:
            resp = self._get(url, JSON_MAX_BYTES)
        except Exception:  # noqa: BLE001 - optional data source
            return None
        if resp.status_code != 200:
            return None
        try:
            return json.loads(resp._capped_content.decode("utf-8", errors="ignore"))
        except ValueError:
            return None
