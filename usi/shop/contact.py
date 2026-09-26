"""Who can be reached, and what the shop promises buyers.

- Contact details: an email, a phone number, a street address. A shop
  with none of them on its front page, contact, about or legal pages has
  no one to complain to - the first thing Watchlist Internet's experts
  check.
- Policy pages: whether returns/refund and terms pages are linked at all.
- Template leftovers: fake shops are cloned by the thousand and their
  policies often keep the template's placeholders ("[store name]",
  "your company name", lorem ipsum).
- Trust seals: a badge image is easy to copy. A real Trusted Shops,
  Norton, Trustpilot or CaseTrust seal links to the issuer's page for
  that shop; one that links nowhere (or back to the shop) proves nothing."""
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from ..models import Severity, Signal
from .pages import Page

IDENTITY = "shop_identity"
COPY = "shop_copy"

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,24}")
_NOT_EMAIL_SUFFIX = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".js", ".css")
_NOT_CONTACT_DOMAINS = ("sentry.io", "sentry-next.wixpress.com", "wixpress.com", "example.com", "domain.com",
                        "email.com", "yourdomain.com", "yourstore.com")
FREEMAIL = ("gmail.com", "googlemail.com", "yahoo.com", "yahoo.com.sg", "ymail.com", "hotmail.com", "outlook.com",
            "live.com", "msn.com", "aol.com", "icloud.com", "me.com", "qq.com", "163.com", "126.com", "gmx.de",
            "gmx.net", "gmx.com", "mail.ru", "yandex.ru", "yandex.com", "proton.me", "protonmail.com", "web.de",
            "zoho.com", "mail.com")

_PHONE_INTL_RE = re.compile(r"(?<![\w/.=-])(?:\+|00)[1-9]\d{0,2}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}(?![\w/])")
_PHONE_LOCAL_RE = re.compile(
    r"(?i)(?:tel|phone|call|hotline|whatsapp|mobile|contact)[^0-9+]{0,20}(\(?\d{2,4}\)?[\s.-]?\d{3,4}(?:[\s.-]?\d{3,4})?)")
_SG_POSTAL_RE = re.compile(r"(?i)\bsingapore\s*[,(]?\s*\d{6}\b|\bS\s?\(\s?\d{6}\s?\)")
_STREET_RE = re.compile(
    r"(?i)\b\d{1,5}[a-z]?,?\s+[a-zäöüéèà' .-]{3,40}?\b(?:street|st\.|road|rd\.?|avenue|ave\.?|lane|drive|boulevard|blvd"
    r"|straße|strasse|str\.|weg|platz|gasse|allee|rue|calle|crescent)\b"
    r"|\b[a-zäöüß-]*(?:straße|strasse|str\.|weg|platz|gasse|allee)\s+\d{1,4}[a-z]?\b"
    r"|\b(?:blk|block)\s?\d{1,4}[a-z]?\b|#\d{1,2}-\d{1,4}\b")   # Singapore block and unit numbers

_PLACEHOLDER_RE = re.compile(
    r"(?i)\[(?:your )?(?:store|shop|company|business|website) ?name\]|\{\{\s*shop\.name\s*\}\}"
    r"|\byour (?:store|shop|company) name\b|\blorem ipsum\b|\binsert (?:your )?(?:company|store|shop) name\b"
    r"|\[(?:your )?email(?: address)?\]|\[(?:your )?(?:phone|address)\]|\bstore name here\b|\bcompany name here\b"
    r"|\bxxx@xxx\b")

# Seal name -> the issuer domains a genuine seal links to.
SEALS = {
    "Trusted Shops": (r"trusted ?shops", ("trustedshops.com", "trustedshops.de", "trustedshops.eu", "trustedshops.co.uk",
                                           "trustedshops.fr", "trustedshops.it", "trustedshops.es", "trustedshops.nl",
                                           "trustedshops.pl", "trustedshops.at", "trustedshops.ch")),
    "Norton": (r"norton ?(?:secured|shopping)", ("norton.com", "trustedsite.com", "nortonshoppingguarantee.com")),
    "McAfee SECURE": (r"mcafee ?secure", ("mcafeesecure.com", "trustedsite.com")),
    "Trustpilot": (r"trustpilot", ("trustpilot.com",)),
    "CaseTrust": (r"case ?trust", ("case.org.sg",)),
    "BBB": (r"bbb accredited|better business bureau", ("bbb.org",)),
    "Sectigo": (r"sectigo|comodo secure|trustlogo", ("sectigo.com", "comodo.com", "trustlogo.com")),
    "DigiCert": (r"digicert", ("digicert.com",)),
}


def find_contacts(pages: "list[Page]") -> dict:
    emails, phones, addresses = set(), set(), set()
    for page in pages:
        for url, _text in page.links:
            if url.lower().startswith("mailto:"):
                emails.add(url[7:].split("?")[0].strip().lower())
            elif url.lower().startswith("tel:"):
                phones.add(re.sub(r"[^\d+]", "", url[4:])[:20])
        for m in _EMAIL_RE.findall(page.text):
            emails.add(m.lower())
        for m in _PHONE_INTL_RE.findall(page.text):
            digits = re.sub(r"\D", "", m)
            if 8 <= len(digits) <= 15:
                phones.add(m.strip())
        for m in _PHONE_LOCAL_RE.findall(page.text):
            if 7 <= len(re.sub(r"\D", "", m)) <= 12:
                phones.add(m.strip())
        for m in _SG_POSTAL_RE.findall(page.text):
            addresses.add(" ".join(m.split()))
        for m in _STREET_RE.finditer(page.text):
            addresses.add(" ".join(m.group(0).split())[:80])
    emails = {e for e in emails
              if "@" in e and not e.endswith(_NOT_EMAIL_SUFFIX)
              and not any(e.endswith("@" + d) or e.endswith("." + d) for d in _NOT_CONTACT_DOMAINS)}
    return {"emails": sorted(emails)[:10], "phones": sorted(phones)[:10], "addresses": sorted(addresses)[:5]}


def contact_signals(contacts: dict, footer_seen: bool = True) -> "list[Signal]":
    """`footer_seen`: whether the front page showed any contact, about or policy link at all. Many shops
    load their whole footer by script; if none of those links came through, missing contact details
    most likely weren't rendered rather than absent, so that is only noted, not weighed as a warning."""
    emails, phones, addresses = contacts["emails"], contacts["phones"], contacts["addresses"]
    if not (emails or phones or addresses):
        if not footer_seen:
            return [Signal(
                source=IDENTITY, code="shop_contact_not_found", severity=Severity.LOW,
                message=("We couldn't find contact details or links to contact and policy pages on the front page. "
                         "They may be loaded by script - look for them yourself before buying."),
                evidence=contacts,
            )]
        return [Signal(
            source=IDENTITY, code="shop_no_contact", severity=Severity.MEDIUM,
            message=("We found no email address, phone number or street address on the pages we checked. "
                     "If something goes wrong there would be no one to contact."),
            evidence=contacts,
        )]
    out = []
    if not phones and not addresses:
        out.append(Signal(
            source=IDENTITY, code="shop_contact_thin", severity=Severity.LOW,
            message="The only contact detail we found is an email address - no phone number or street address.",
            evidence=contacts,
        ))
    domains = {e.rsplit("@", 1)[1] for e in emails}
    if emails and domains and all(d in FREEMAIL or d.startswith("yahoo.") or d.startswith("hotmail.") for d in domains):
        out.append(Signal(
            source=IDENTITY, code="shop_freemail_contact", severity=Severity.LOW,
            message=(f"The shop's email address uses a free webmail service ({', '.join(sorted(domains))}) "
                     "rather than the shop's own domain. Small genuine sellers do this too, but it hides who is behind it."),
            evidence={"emails": emails},
        ))
    out.append(Signal(
        source=IDENTITY, code="shop_contact", severity=Severity.INFO,
        message="Contact details found: " + ", ".join(
            x for x in (f"{len(emails)} email" if emails else "", f"{len(phones)} phone" if phones else "",
                        f"{len(addresses)} address" if addresses else "") if x) + ".",
        evidence=contacts,
    ))
    return out


def policy_signals(links_by_kind: "dict[str, list[str]]") -> "list[Signal]":
    present = sorted(k for k in ("refund", "terms", "privacy", "shipping") if links_by_kind.get(k))
    if not links_by_kind.get("refund") and not links_by_kind.get("terms"):
        return [Signal(
            source=IDENTITY, code="shop_no_policies", severity=Severity.LOW,
            message="The shop's front page doesn't link to a returns/refund policy or to terms of sale.",
            evidence={"policy_pages": present},
        )]
    return [Signal(
        source=IDENTITY, code="shop_policies", severity=Severity.INFO,
        message="Policy pages linked: " + ", ".join(present) + ".",
        evidence={"policy_pages": present},
    )]


def template_signals(pages: "list[Page]") -> "list[Signal]":
    for page in pages:
        m = _PLACEHOLDER_RE.search(page.text)
        if m:
            start = max(0, m.start() - 60)
            snippet = page.text[start:m.end() + 60]
            return [Signal(
                source=COPY, code="shop_template_text", severity=Severity.MEDIUM,
                message=(f"The page {urlparse(page.url).path or '/'} still contains template placeholder text "
                         f"(\"{m.group(0)}\"). Shops copied in bulk from one template often leave this behind."),
                evidence={"page": page.url, "snippet": " ".join(snippet.split())[:200]},
            )]
    return []


def _issuer_link(el) -> "str | None":
    a = el if el.name == "a" else el.find_parent("a")
    return a.get("href") if a is not None and a.get("href") else None


def seal_signals(page: Page) -> "list[Signal]":
    soup = BeautifulSoup(page.html, "lxml")
    unlinked, linked = [], []
    for el in soup.find_all(["img", "a", "svg"]):
        attrs = " ".join(str(el.get(a) or "") for a in ("alt", "src", "title", "class", "aria-label", "data-src")).lower()
        if el.name == "a":
            attrs += " " + (el.get("href") or "").lower()
        for seal, (rx, issuers) in SEALS.items():
            if seal in linked or seal in unlinked or not re.search(rx, attrs):
                continue
            href = _issuer_link(el)
            link_host = (urlparse(href).hostname or "").lower() if href else ""
            if link_host and any(link_host == d or link_host.endswith("." + d) for d in issuers):
                linked.append(seal)
            elif el.name == "img":
                unlinked.append(seal)
    # A seal that also appears correctly linked elsewhere on the page is fine.
    unlinked = [s for s in unlinked if s not in linked]
    out = []
    if unlinked:
        out.append(Signal(
            source=COPY, code="shop_seal_unlinked", severity=Severity.LOW,
            message=(f"The page shows a {', '.join(unlinked)} badge that doesn't link to the issuer's own site. "
                     "A genuine seal opens the issuer's page for this shop; a bare image can be copied by anyone."),
            evidence={"unlinked": unlinked, "linked": linked},
        ))
    if "CaseTrust" in unlinked or re.search(r"(?i)case ?trust", page.text):
        out.append(Signal(
            source=COPY, code="shop_mentions_casetrust", severity=Severity.INFO,
            message="The shop mentions CaseTrust accreditation. Check its name in CASE's CaseTrust directory (case.org.sg).",
        ))
    return out
