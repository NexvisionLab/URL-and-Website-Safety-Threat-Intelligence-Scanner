"""Brand-impersonation check: the page names a known brand (in its title
or visible body text) AND has an actual password input field - the
domain serving it isn't that brand's real domain (or a legitimate
subdomain of it).

The password field is the load-bearing gate, not where on the page the
brand name appears. Matching the brand name in the <title> only misses
real phishing clones, whose title is often generic ("Sign in to your
account") while the brand shows up in the body/logo text; matching it
anywhere with no structural gate fires on legitimate pages that merely
mention another company. What separates "this page mentions a brand"
from "this page is built to collect that brand's password" is a real
<input type="password"> field, so that is required, and the brand name
is searched in both the title and the visible text."""
import tldextract

from ..models import Severity, Signal


def check(
    host: str,
    page_title: "str | None",
    page_text: "str | None",
    has_password_field: bool,
    brands: "list[dict]",
) -> "Signal | None":
    if not has_password_field:
        return None
    haystack = f"{page_title or ''} {page_text or ''}".lower()
    if not haystack.strip():
        return None

    host_l = host.lower()
    ext = tldextract.extract(host_l)
    registrable = f"{ext.domain}.{ext.suffix}" if ext.suffix else host_l

    for brand in brands:
        name_l = brand["name"].lower()
        real_domains = [d.lower() for d in brand["domains"]]
        if registrable in real_domains or any(host_l.endswith("." + d) for d in real_domains):
            continue  # this IS (a subdomain of) the real brand - nothing to flag
        if name_l in haystack:
            return Signal(
                source="brand_impersonation", code="brand_impersonation",
                severity=Severity.HIGH,
                message=(
                    f"This page references '{brand['name']}' and has a password field, "
                    f"but it is served from '{host}', which is not a known "
                    f"{brand['name']} domain."
                ),
                evidence={"brand": brand["name"], "host": host, "title": page_title},
            )
    return None
