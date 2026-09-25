from usi.models import Severity
from usi.shop import contact, pages


def page(text="", html="", url="https://shop.example/", links=None):
    return pages.Page(url=url, html=html, text=text, links=links or [])


def codes(signals):
    return [s.code for s in signals]


def test_contacts_found_in_text_and_links():
    p = page(text="Call us +65 6232 6720 or visit 10 Anson Road #12-08 Singapore 079903. hello@shop.example",
             links=[("mailto:sales@shop.example?subject=hi", "mail"), ("tel:+6562326720", "call")])
    c = contact.find_contacts([p])
    assert c["emails"] == ["hello@shop.example", "sales@shop.example"]
    assert "+6562326720" in c["phones"]
    assert "Singapore 079903" in c["addresses"] and "#12-08" in c["addresses"]
    assert codes(contact.contact_signals(c)) == ["shop_contact"]


def test_image_names_and_placeholders_are_not_emails():
    c = contact.find_contacts([page(text="logo@2x.png support@example.com")])
    assert c["emails"] == []


def test_no_contact_at_all_is_medium():
    sig = contact.contact_signals(contact.find_contacts([page(text="Best deals! Buy now!")]))
    assert codes(sig) == ["shop_no_contact"] and sig[0].severity == Severity.MEDIUM


def test_missing_footer_is_only_a_note():
    sig = contact.contact_signals(contact.find_contacts([page(text="Best deals! Buy now!")]), footer_seen=False)
    assert codes(sig) == ["shop_contact_not_found"] and sig[0].severity == Severity.LOW


def test_singapore_local_number_after_hotline():
    c = contact.find_contacts([page(text="Customer service hotline: 6333 5858, 9am to 6pm")])
    assert "6333 5858" in c["phones"]


def test_email_only_and_freemail():
    sig = contact.contact_signals(contact.find_contacts([page(text="Contact: bestdeals.store@gmail.com")]))
    assert codes(sig) == ["shop_contact_thin", "shop_freemail_contact", "shop_contact"]


def test_german_street_address():
    c = contact.find_contacts([page(text="Impressum: Muster GmbH, Hauptstraße 37, 10115 Berlin")])
    assert any("37" in a for a in c["addresses"])


def test_ordinary_sentence_is_not_an_address():
    assert contact.find_contacts([page(text="Get a S$10 birthday voucher sent via email")])["addresses"] == []


def test_policy_pages():
    assert codes(contact.policy_signals({})) == ["shop_no_policies"]
    assert codes(contact.policy_signals({"refund": ["https://s/refund"]})) == ["shop_policies"]


def test_template_placeholder_text():
    sig = contact.template_signals([page(text="Returns are handled by [Store Name] within 14 days.",
                                         url="https://s/pages/refund")])
    assert codes(sig) == ["shop_template_text"] and "/pages/refund" in sig[0].message
    assert contact.template_signals([page(text="Returns are handled by Acme within 14 days.")]) == []


def test_unlinked_seal_is_flagged_and_linked_seal_is_not():
    bare = page(html='<img src="/img/trusted-shops-badge.png" alt="Trusted Shops">')
    assert codes(contact.seal_signals(bare)) == ["shop_seal_unlinked"]
    linked = page(html='<a href="https://www.trustedshops.de/bewertung/info_X.html">'
                       '<img src="/img/trustedshops.png" alt="Trusted Shops"></a>')
    assert contact.seal_signals(linked) == []
    self_linked = page(html='<a href="/about"><img alt="Norton Secured" src="n.png"></a>')
    assert codes(contact.seal_signals(self_linked)) == ["shop_seal_unlinked"]


def test_casetrust_mention_points_to_the_directory():
    sig = contact.seal_signals(page(text="We are CaseTrust accredited", html="<p>We are CaseTrust accredited</p>"))
    assert codes(sig) == ["shop_mentions_casetrust"] and sig[0].severity == Severity.INFO
