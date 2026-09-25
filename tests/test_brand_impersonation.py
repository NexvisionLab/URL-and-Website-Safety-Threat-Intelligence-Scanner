from usi.content import brand_impersonation

BRANDS = [{"name": "Microsoft", "domains": ["microsoft.com", "live.com"]}]


def test_incidental_mention_without_password_field_not_flagged():
    # Regression 1: a legitimate page that merely mentions a brand name,
    # with no password field, must not be flagged - this was the original
    # false "Likely Malicious" on a real company site.
    sig = brand_impersonation.check(
        host="example-software.com",
        page_title="How we partnered with Microsoft on Azure",
        page_text="We're excited to announce our partnership with Microsoft. "
                   "Sign in to your account to learn more.",
        has_password_field=False,
        brands=BRANDS,
    )
    assert sig is None


def test_brand_in_body_text_with_password_field_is_flagged():
    # Regression 2: a real confirmed phishing clone (OpenPhish feed) whose
    # <title> was the generic "Sign in to your account" with "Microsoft"
    # only in the visible body/logo text - must still be caught.
    sig = brand_impersonation.check(
        host="microsoft-0r.github.io",
        page_title="Sign in to your account",
        page_text="Sign in to your account Microsoft Enter password Sign in "
                   "with another account Password Forgot password?",
        has_password_field=True,
        brands=BRANDS,
    )
    assert sig is not None
    assert sig.code == "brand_impersonation"


def test_brand_title_plus_password_field_is_flagged():
    sig = brand_impersonation.check(
        host="micros0ft-login.top",
        page_title="Sign in - Microsoft Account",
        page_text="",
        has_password_field=True,
        brands=BRANDS,
    )
    assert sig is not None


def test_real_brand_domain_never_flagged_even_with_password_field():
    sig = brand_impersonation.check(
        host="login.live.com",
        page_title="Sign in - Microsoft Account",
        page_text="Microsoft sign in",
        has_password_field=True,
        brands=BRANDS,
    )
    assert sig is None


def test_no_title_or_text_not_flagged():
    sig = brand_impersonation.check(
        host="evil.top", page_title=None, page_text=None, has_password_field=True, brands=BRANDS,
    )
    assert sig is None


def test_unrelated_brand_not_flagged():
    sig = brand_impersonation.check(
        host="example.com", page_title="Welcome to Example", page_text="",
        has_password_field=True, brands=BRANDS,
    )
    assert sig is None
