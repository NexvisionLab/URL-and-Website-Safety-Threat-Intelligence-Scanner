"""Brand matching fixes (2026-09-27), from a test of ten real phishing pages in OpenPhish's public feed of which the
checker caught two: dotted brand names, brand aliases, brand names on free-hosting subdomains, and more brands.
The host names below are real phishing hosts from that feed, or real sites that must not be flagged."""
import pytest

from usi.heuristics import typosquat
from usi.models import Severity

BRANDS = typosquat.load_brands()


def signal(host):
    sigs = typosquat.run_all(host, BRANDS)
    return sigs[0] if sigs else None


def high(host):
    s = signal(host)
    return s is not None and s.severity >= Severity.HIGH


# --- a brand whose name contains a dot could never match
def test_booking_com_lookalike_is_now_matched():
    s = signal("secure-checkout-booking.com")
    assert s is not None and s.code == "combosquat_keyword_match"
    assert s.severity == Severity.HIGH  # "secure" is a lure word on top of the brand
    assert "The real Booking.com website is booking.com." in s.message
    assert s.evidence["brand_is_whole_label"] is True  # "booking" stands as its own word, so an unreachable page reads Suspicious


def test_booking_com_lookalike_without_a_lure_word_is_medium():
    s = signal("booking-deals-online.net")
    assert s is not None and s.severity == Severity.MEDIUM


def test_gov_uk_is_matched_by_its_full_name():
    assert signal("gov-uk-refund-claim.com") is not None


def test_dotted_real_sites_are_not_flagged():
    for host in ("booking.com", "www.booking.com", "admin.booking.com", "gov.uk", "www.gov.uk", "assets.publishing.service.gov.uk"):
        assert signal(host) is None, host


# --- aliases: the fake Outlook page on Weebly
def test_alias_matches_and_points_at_the_real_domain():
    s = signal("connexioncompteoutlook.weebly.com")
    assert s.severity == Severity.HIGH
    assert s.evidence["free_hosting"] == "weebly.com"
    assert "brand name 'outlook'" in s.message
    assert "The real Microsoft website is outlook.com." in s.message


def test_facebook_alias_names_facebook_not_meta():
    s = signal("nfacebook.vn")
    assert s is not None and "brand name 'facebook'" in s.message
    assert "The real Meta website is facebook.com." in s.message


# --- a brand name on a free-hosting subdomain
def test_brand_with_digits_on_free_hosting_is_high():
    s = signal("netflix-71f05.firebaseapp.com")
    assert s.severity == Severity.HIGH
    assert s.evidence["free_hosting"] == "firebaseapp.com"
    assert "free hosting service (firebaseapp.com)" in s.message


def test_brand_alone_on_free_hosting_is_only_medium():
    for host in ("netflix.github.io", "microsoft.github.io", "steam-punk-shop.wixsite.com", "allegro-music.blogspot.com"):
        s = signal(host)
        assert s is None or s.severity < Severity.HIGH, host


def test_a_brand_word_inside_another_word_is_not_a_lure():
    s = signal("metallica-fans.com")
    assert s is not None and s.severity == Severity.MEDIUM and s.evidence["brand_is_whole_label"] is False


# --- the brands that were missing
@pytest.mark.parametrize("host", [
    "www.roblox.com.am", "roblox.com.ml", "flipkart.com-nw.in", "allegrolokalnie.pl-fesd.sbs", "discord-gift-nitro.com", "shopee2178.blogspot.com",
])
def test_added_brands_are_now_matched(host):
    assert signal(host) is not None, host


@pytest.mark.parametrize("host", [
    "roblox.com", "www.roblox.com", "create.roblox.com", "flipkart.com", "seller.flipkart.com", "trezor.io", "suite.trezor.io",
    "allegro.pl", "allegro.cz", "allegrolokalnie.pl", "discord.com", "discord.gg", "shopee.sg", "shopee.co.id", "t.me", "web.telegram.org",
])
def test_the_real_sites_of_the_added_brands_are_not_flagged(host):
    assert signal(host) is None, host


# --- false-alarm sweep: real sites (regional domains, platform-hosted official pages, everyday words) must never reach HIGH
REAL_HOSTS = """
google.com www.google.com google.com.au maps.google.com gmail.com youtube.com apple.com apple.com.au icloud.com support.apple.com
amazon.com amazon.com.au amazon.co.uk amazon.de aws.amazon.com microsoft.com support.microsoft.com learn.microsoft.com outlook.live.com
outlook.office.com login.microsoftonline.com paypal.com paypal.com.au netflix.com help.netflix.com spotify.com open.spotify.com
facebook.com instagram.com whatsapp.com web.whatsapp.com messenger.com twitter.com x.com linkedin.com github.com microsoft.github.io google.github.io
netflix.github.io airbnb.github.io reddit.com wikipedia.org en.wikipedia.org bbc.co.uk nytimes.com stripe.com dhl.com fedex.com ups.com usps.com
royalmail.com auspost.com.au singpost.com dbs.com.sg ocbc.com uob.com.sg chase.com bankofamerica.com wellsfargo.com citi.com hsbc.com
ebay.com etsy.com walmart.com target.com costco.com ikea.com aliexpress.com shein.com zalando.com booking.com airbnb.com steampowered.com
steamcommunity.com store.steampowered.com coinbase.com binance.com kraken.com ledger.com metamask.io zoom.us dropbox.com docusign.com adobe.com
""".split()


def test_no_real_site_reaches_high():
    flagged = [h for h in REAL_HOSTS if high(h)]
    assert flagged == [], flagged


def test_everyday_words_that_contain_a_brand_name_do_not_reach_high():
    for host in ("applepie-recipes.com", "pineapple.com", "metallica-fans.com", "instagrammer-tips.com", "discordant-music.net",
                 "steam-punk-shop.wixsite.com", "telegramming.net", "shopeeple.org", "myallegro-music.com"):
        assert not high(host), host


# --- the ten real phishing hosts from the test: how many now carry a warning at all
PHISHING_HOSTS = [
    "www.bankofamerica.xin", "flipkart.com-nw.in", "www.roblox.com.am", "secure-checkout-booking.com",
    "microsoft.authorised-support.com", "connexioncompteoutlook.weebly.com", "netflix-71f05.firebaseapp.com",
    "allegrolokalnie.pl-fesd.sbs",
]


def test_the_phishing_hosts_that_carry_a_brand_name_now_have_a_signal():
    missing = [h for h in PHISHING_HOSTS if signal(h) is None]
    assert missing == [], missing


# --- a brand's own page on GitHub/GitLab Pages (microsoft.github.io read "Likely Malicious" in the live checker)
def test_a_brands_own_github_pages_site_is_not_flagged():
    for host in ("microsoft.github.io", "google.github.io", "netflix.github.io", "paypal.github.io", "microsoft.gitlab.io"):
        assert signal(host) is None, host


def test_the_exemption_is_only_for_the_exact_name_on_platforms_where_names_are_owned():
    assert typosquat.is_official_org_page("microsoft.github.io", BRANDS)
    for host in ("microsoft-login.github.io", "microsoft.weebly.com", "paypal.wixsite.com", "a.microsoft.github.io",
                 "microsoftx.github.io", "microsoft.com", "example.github.io"):
        assert not typosquat.is_official_org_page(host, BRANDS), host


def test_lookalikes_on_github_pages_and_claimable_names_elsewhere_are_still_flagged():
    assert high("secure-paypal-verify.github.io")
    assert high("microsoft-login.github.io")
    assert signal("paypal.weebly.com") is not None  # anyone can claim this name on Weebly


# --- brand aliases on GitHub Pages are the brand's own too (onedrive.github.io read Likely Malicious)
def test_a_brands_alias_on_github_pages_is_the_brands_own():
    for host in ("onedrive.github.io", "facebook.github.io", "instagram.github.io", "outlook.github.io"):
        assert typosquat.is_official_org_page(host, BRANDS), host
        assert signal(host) is None, host


# --- an exact brand-name page on a host where anyone can claim any name (paypal.weebly.com read Likely Safe)
def test_an_exact_brand_name_on_a_claimable_free_host_is_high():
    for host in ("paypal.weebly.com", "netflix.wixsite.com", "microsoft.blogspot.com", "bank-of-america.weebly.com", "spotify.vercel.app"):
        s = signal(host)
        assert s is not None and s.severity == Severity.HIGH, host
        assert "named exactly like the brand" in s.message, host
        assert s.evidence["free_hosting"], host


def test_short_ordinary_word_brands_are_not_raised_on_a_free_host():
    for host in ("apple.weebly.com", "steam.wixsite.com", "zoom.blogspot.com", "meta.weebly.com", "visa.weebly.com"):
        assert not high(host), host


def test_a_similar_but_not_exact_name_on_a_free_host_is_unchanged():
    assert signal("paypalfans.weebly.com").severity == Severity.MEDIUM
    assert not high("steam-punk-shop.wixsite.com")


def test_the_exact_name_rule_does_not_reach_github_or_gitlab_pages():
    assert signal("paypal.github.io") is None and signal("paypal.gitlab.io") is None

