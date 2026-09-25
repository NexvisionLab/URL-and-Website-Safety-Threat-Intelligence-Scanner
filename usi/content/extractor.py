"""HTML -> title/visible-text/forms/links extraction. Takes the raw HTML
a FetchResult carries in .text and returns a new FetchResult with that
field replaced by cleaned visible text, plus the structured fields the
brand-impersonation and classifier layers need."""
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from ..models import FetchResult

# Generous ceiling only (the fetch itself is already byte-capped). Every
# pattern-based check (ClickFix, fake-meeting, fee scams) reads this text,
# so a tight cap here lets a scam page hide its instruction below filler;
# the embedding classifier truncates for itself where it needs to.
TEXT_TRUNCATE_CHARS = 1_000_000


def extract(raw_html: str, base_url: str, http_status: "int | None", final_url: "str | None") -> FetchResult:
    soup = BeautifulSoup(raw_html, "lxml")

    for tag in soup(["script", "style"]):
        tag.decompose()

    title = soup.title.get_text(strip=True) if soup.title else None
    text = " ".join(soup.get_text(separator=" ").split())[:TEXT_TRUNCATE_CHARS]

    has_password_field = soup.find("input", {"type": "password"}) is not None

    form_actions = []
    for form in soup.find_all("form"):
        action = form.get("action") or ""
        resolved = urljoin(final_url or base_url, action)
        form_actions.append(resolved)

    external_links = []
    base_host = urlparse(final_url or base_url).hostname
    for a in soup.find_all("a", href=True):
        resolved = urljoin(final_url or base_url, a["href"])
        link_host = urlparse(resolved).hostname
        if link_host and link_host != base_host:
            external_links.append(resolved)

    return FetchResult(
        reachable=True,
        http_status=http_status,
        final_url=final_url,
        title=title,
        text=text,
        has_password_field=has_password_field,
        form_actions=form_actions,
        external_links=external_links[:20],
    )
