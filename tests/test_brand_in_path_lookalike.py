"""Brand-in-path lookalike (2026-10-20): a brand name that appears only in the URL PATH, not the host at
all. Documented real case from the 2026-09-27 OpenPhish sample:
verifiedbadge-celestine.vercel.app/meta-verified-for-business impersonating Meta. Every other brand check
here looks only at the host, so a host with no brand reference whatsoever sails through them even when the
page it points at clearly targets that brand by name in its own address."""
from usi.heuristics import typosquat
from usi.models import Severity

BRANDS = typosquat.load_brands()


def signal(url, host):
    return typosquat.find_brand_in_path_lookalike(url, host, BRANDS)


# --- must fire ---

def test_reported_meta_verified_lookalike_is_caught():
    s = signal("https://verifiedbadge-celestine.vercel.app/meta-verified-for-business",
               "verifiedbadge-celestine.vercel.app")
    assert s is not None and s.code == "brand_in_path_lookalike"
    assert s.severity == Severity.HIGH
    assert s.evidence["brand"] == "Meta"
    assert s.evidence["free_hosting"] == "vercel.app"


def test_brand_plus_lure_word_in_path_on_a_free_host_is_caught():
    s = signal("https://mysite.weebly.com/paypal-login-verify", "mysite.weebly.com")
    assert s is not None and s.evidence["brand"] == "PayPal"


def test_lure_word_in_query_string_also_counts():
    s = signal("https://mysite.weebly.com/account?brand=apple&action=verify", "mysite.weebly.com")
    assert s is not None and s.evidence["brand"] == "Apple"


# --- must NOT fire ---

def test_ordinary_hosts_are_never_checked_at_all():
    # not a free-hosting suffix - a brand name in the path of an ordinary site (a review, a blog post) is
    # extremely common and not itself a signal.
    s = signal("https://example.com/reviews/best-nike-shoes-2026", "example.com")
    assert s is None


def test_brand_name_alone_with_no_lure_word_is_not_enough():
    s = signal("https://mysite.weebly.com/blog/best-nike-shoes-review", "mysite.weebly.com")
    assert s is None


def test_a_page_with_no_brand_at_all_is_clean():
    s = signal("https://mysite.weebly.com/not-a-brand-page-at-all", "mysite.weebly.com")
    assert s is None


def test_a_brand_name_as_a_substring_of_an_unrelated_word_does_not_trip_it():
    # "meta" inside "metacritic" is a different token, not a standalone path segment.
    s = signal("https://randomsite.vercel.app/metacritic-reviews-verify", "randomsite.vercel.app")
    assert s is None


def test_github_and_gitlab_pages_are_excluded_as_the_brands_own_namespace():
    s = signal("https://microsoft.github.io/some-verify-login-page", "microsoft.github.io")
    assert s is None


def test_the_brands_own_real_domain_is_never_checked():
    s = signal("https://support.apple.com/apple-verify-account", "support.apple.com")
    assert s is None


def test_a_three_character_fragment_cannot_trip_it():
    # Guard against very short names matching too eagerly; brands.json has none under 4 chars, but confirm
    # the length gate is enforced by checking a 3-char fragment never matches via the free-host+lure path.
    s = signal("https://mysite.weebly.com/abc-login-verify", "mysite.weebly.com")
    assert s is None
