"""Orchestrates every investigation layer in order and builds the final
InvestigationResult. This is the one place that knows the full pipeline
shape; individual layer modules stay independently testable."""
from datetime import datetime, timezone
from urllib.parse import urlparse

from . import cache
from .config import Config
from .heuristics import lexical_url, punycode, redirect_chain, typosquat, url_structure
from .models import InvestigationResult, Severity, Signal
from .verdict import aggregator


class InvalidTargetError(ValueError):
    """The input can't be interpreted as an http(s) URL or bare host."""


def normalize_target(raw: str) -> "tuple[str, str]":
    """Returns (url, host). Adds a scheme if missing so urlparse behaves.
    Raises InvalidTargetError for input that isn't a usable http(s)
    target - crafted URLs are exactly what this tool is pointed at, so
    a malformed port/IPv6 literal must be a clean error, and empty or
    non-http input must never come back as a reassuring "Likely Safe".
    A trailing dot on the host ("paypal.com.") is stripped so it can't
    sidestep exact-domain comparisons."""
    raw = (raw or "").strip()
    if not raw:
        raise InvalidTargetError("no URL or domain was given")
    url = raw if "://" in raw else f"http://{raw}"
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        parsed.port  # noqa: B018 - raises ValueError on a non-numeric/out-of-range port
    except ValueError as e:
        raise InvalidTargetError(f"malformed URL ({e})") from e
    if parsed.scheme.lower() not in ("http", "https"):
        raise InvalidTargetError(
            f"unsupported scheme '{parsed.scheme}' (only http/https targets are investigated)"
        )
    if not host or any(c.isspace() or ord(c) < 32 for c in host):
        raise InvalidTargetError("the input has no valid host name")
    return url, host.rstrip(".")


def run(
    raw_target: str,
    config: Config,
    *,
    offline: bool = False,
    no_fetch: bool = False,
    no_external: bool = False,
    no_cache: bool = False,
    no_store: bool = False,
    cache_ttl_hours: "int | None" = None,
    brands_path=None,
) -> InvestigationResult:
    url, host = normalize_target(raw_target)
    is_onion = host.lower().endswith(".onion")
    ttl = cache_ttl_hours if cache_ttl_hours is not None else config.cache_ttl_hours
    skipped: "list[str]" = []

    if not no_cache:
        cached = cache.get(config.cache_path, url, ttl)
        if cached is not None:
            from .output.formatter import result_from_dict
            result = result_from_dict(cached)
            result.from_cache = True
            return result

    signals: "list[Signal]" = []

    # 1. Static heuristics - always run, no network.
    signals += url_structure.run_all(url, host)
    signals += punycode.run_all(host)
    signals += lexical_url.analyze(host)
    brands = typosquat.load_brands(brands_path) if brands_path else typosquat.load_brands()
    signals += typosquat.run_all(host, brands)

    typosquat_match = next((s for s in signals if s.code == "typosquat_match"), None)

    if offline:
        skipped += ["whois", "tls_cert", "crtsh", "fetch", "classifier",
                    "brand_impersonation", "favicon", "clickfix", "crypto_drainer",
                    "delivery_fee", "redirect_chain", "cloaking", "prompt_injection", "shop_check",
                    "reputation"]
    else:
        # 2. WHOIS
        from .lookups import whois_lookup
        signals += whois_lookup.lookup(host, skip=is_onion)
        if is_onion:
            skipped.append("whois (.onion)")

        # 3. TLS cert (clearnet only, only meaningful for https targets)
        from .lookups import tls_cert
        signals += tls_cert.inspect(host, skip=is_onion)
        if is_onion:
            skipped.append("tls_cert (.onion)")

        # 4. crt.sh corroboration of the investigated host itself, only if
        # it was already matched as a typosquat of a known brand
        if typosquat_match:
            from .lookups import crtsh
            signals += crtsh.check_lookalike_host(host)

        if no_fetch:
            skipped.append("fetch")
            signals.append(Signal(
                source="fetch", code="fetch_skipped", severity=Severity.INFO,
                message="Live page fetch skipped (--no-fetch).",
            ))
        else:
            # 5. Live fetch + extraction + classification + brand check
            from .content import (
                brand_impersonation, classifier, clickfix, cloaking, crypto_drainer, delivery_fee,
                extractor, fake_meeting, favicon, fetcher, prompt_injection, shop_check,
            )
            tor_proxy = config.tor_proxy if (is_onion or config.tor_enabled) else None
            fetch_result = fetcher.fetch(
                url, timeout=config.fetch_timeout_seconds, max_bytes=config.fetch_max_bytes,
                user_agent=config.fetch_user_agent, tor_proxy=tor_proxy,
            )
            if not fetch_result.reachable:
                signals.append(Signal(
                    source="fetch", code="fetch_failed", severity=Severity.INFO,
                    message=f"Could not fetch the page: {fetch_result.error}",
                ))
            else:
                # Download detection runs on the raw response headers
                # regardless of whether the body decoded as HTML - a
                # binary/attachment response has no text to extract, but
                # is exactly the case this check exists for.
                from .content import download_check
                download_signal = download_check.analyze(
                    fetch_result.final_url or url, fetch_result.content_type,
                    fetch_result.content_disposition,
                )
                if download_signal:
                    signals.append(download_signal)

                raw_html = fetch_result.text or ""
                extracted = extractor.extract(
                    raw_html, url, fetch_result.http_status, fetch_result.final_url
                )
                if extracted.has_password_field:
                    signals.append(Signal(
                        source="fetch", code="password_field_present", severity=Severity.INFO,
                        message="This page contains a password input field.",
                    ))
                cross_domain_forms = [
                    a for a in extracted.form_actions
                    if urlparse(a).hostname and urlparse(a).hostname != host
                ]
                if cross_domain_forms and extracted.has_password_field:
                    signals.append(Signal(
                        source="fetch", code="cross_domain_form_post", severity=Severity.HIGH,
                        message="A password field on this page submits to a different domain.",
                        evidence={"targets": cross_domain_forms[:3]},
                    ))

                classifier_signal = classifier.classify(extracted.text)
                if classifier_signal:
                    signals.append(classifier_signal)

                impersonation_signal = brand_impersonation.check(
                    host, extracted.title, extracted.text, extracted.has_password_field, brands
                )
                if impersonation_signal:
                    signals.append(impersonation_signal)

                fake_meeting_signal = fake_meeting.check(host, extracted.title, extracted.text, raw_html)
                if fake_meeting_signal:
                    signals.append(fake_meeting_signal)

                # Favicon hash match - works even on JS-rendered pages this
                # tool's non-JS fetcher can't otherwise see into, since the
                # favicon is a static asset declared in <head>.
                favicon_url = favicon.find_declared_favicon_url(
                    raw_html, fetch_result.final_url or url
                )
                favicon_signal = favicon.check(
                    host, favicon_url, config.fetch_user_agent, brands, tor_proxy=tor_proxy
                )
                if favicon_signal:
                    signals.append(favicon_signal)

                clickfix_signal = clickfix.check(extracted.text, raw_html)
                if clickfix_signal:
                    signals.append(clickfix_signal)

                prompt_injection_signal = prompt_injection.check(raw_html)
                if prompt_injection_signal:
                    signals.append(prompt_injection_signal)

                drainer_signal = crypto_drainer.check(extracted.title, extracted.text, raw_html)
                if drainer_signal:
                    signals.append(drainer_signal)

                delivery_signal = delivery_fee.check(extracted.text)
                if delivery_signal:
                    signals.append(delivery_signal)

                toll_signal = delivery_fee.check_toll(extracted.text)
                if toll_signal:
                    signals.append(toll_signal)

                # Fake-shop signs. Silent unless the page is recognisably a shop; reads the WHOIS age gathered above.
                signals += shop_check.check(host, extracted.title, extracted.text, raw_html, signals)

                # Redirect-chain analysis over the hops requests followed.
                final_host = urlparse(fetch_result.final_url or url).hostname or host
                signals += redirect_chain.analyze(host, final_host, fetch_result.redirect_chain)

                # Cloaking check - one extra, disclosed comparison request
                # with a standard browser UA (see cloaking.py's docstring
                # on why this doesn't contradict the honest-UA guardrail).
                # Skipped for a direct file download (fetch_result.text is
                # None): the "size" being compared would be 0 decoded-text
                # bytes vs. the comparison fetch's real file bytes, which
                # is always a mismatch and tells us nothing about cloaking
                # - it's an artifact of the response not being a page at
                # all, not evidence of UA-based content switching.
                cloaking_signal = cloaking.check(
                    url, fetch_result.http_status, len(raw_html),
                    timeout=config.fetch_timeout_seconds, max_bytes=config.fetch_max_bytes,
                    tor_proxy=tor_proxy, primary_html=raw_html,
                ) if fetch_result.text is not None else None
                if cloaking_signal:
                    signals.append(cloaking_signal)

        # 6. Optional reputation APIs
        if no_external or not config.reputation_enabled:
            skipped.append("reputation")
        else:
            from .reputation.abuseipdb import AbuseIPDBClient
            from .reputation.safe_browsing import SafeBrowsingClient
            from .reputation.urlscan import UrlscanClient
            from .reputation.virustotal import VirusTotalClient

            clients = [
                SafeBrowsingClient(config.reputation["safe_browsing"].api_key, config.reputation["safe_browsing"].enabled),
                VirusTotalClient(config.reputation["virustotal"].api_key, config.reputation["virustotal"].enabled),
                UrlscanClient(config.reputation["urlscan"].api_key, config.reputation["urlscan"].enabled),
                AbuseIPDBClient(config.reputation["abuseipdb"].api_key, config.reputation["abuseipdb"].enabled),
            ]
            for client in clients:
                result_signal = client.check(url, host)
                if result_signal:
                    signals.append(result_signal)

    verdict = aggregator.rate(signals)
    result = InvestigationResult(
        url=url, host=host, is_onion=is_onion, from_cache=False,
        checked_at=datetime.now(timezone.utc).isoformat(),
        verdict=verdict, skipped_layers=skipped,
    )

    if not no_store:
        from .output.formatter import result_to_dict
        cache.set(config.cache_path, url, result_to_dict(result))

    return result
