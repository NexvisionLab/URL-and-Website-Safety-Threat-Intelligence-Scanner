"""Argument parsing + orchestration entry point."""
import argparse
import sys
from pathlib import Path

from . import __version__
from .config import load_config
from .output.formatter import to_human_report, to_json
from .pipeline import InvalidTargetError, run


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="investigate.py",
        description="Investigate whether a URL/site is likely phishing, a scam, "
                     "malware-distributing, or legitimate. Standalone tool - no "
                     "external service required for a full result.",
    )
    p.add_argument("url", help="Target URL or bare domain (clearnet or .onion)")

    net = p.add_argument_group("network / mode")
    net.add_argument("--tor", action="store_true", help="Route fetch/lookups through a Tor SOCKS proxy")
    net.add_argument("--tor-proxy", metavar="HOST:PORT", help="Override Tor proxy address")
    net.add_argument("--offline", action="store_true", help="Static heuristics only, zero network calls")
    net.add_argument("--no-fetch", action="store_true", help="Skip the live page fetch")
    net.add_argument("--no-external", action="store_true", help="Force-disable optional reputation APIs")
    net.add_argument("--timeout", type=int, metavar="SECONDS", help="Override fetch timeout")
    net.add_argument("--max-bytes", type=int, metavar="N", help="Override fetch byte cap")

    cache_grp = p.add_argument_group("cache")
    cache_grp.add_argument("--no-cache", action="store_true", help="Ignore any cached entry for this run")
    cache_grp.add_argument("--no-store", action="store_true", help="Don't write this result to the cache")
    cache_grp.add_argument("--refresh", action="store_true", help="Shorthand for --no-cache")
    cache_grp.add_argument("--cache-ttl", type=int, metavar="HOURS", help="Override cache TTL")

    cfg_grp = p.add_argument_group("config / data")
    cfg_grp.add_argument("--config", type=Path, help="Path to config.toml")
    cfg_grp.add_argument("--brands", type=Path, help="Override path to data/brands.json")

    out = p.add_argument_group("output")
    out.add_argument("--json", action="store_true", help="Machine-readable output")
    out.add_argument("-v", "--verbose", action="store_true", help="Show every signal, not just LOW+")
    out.add_argument("-q", "--quiet", action="store_true", help="Only print the final verdict line")
    out.add_argument("--version", action="version", version=f"url-safety-investigator {__version__}")

    return p


def main(argv=None) -> int:
    # Windows consoles often default to a legacy codepage (cp1252) that
    # can't encode the box-drawing/unicode characters rich's report uses -
    # force UTF-8 stdout regardless of platform default.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    args = build_parser().parse_args(argv)
    config = load_config(args.config)

    if args.tor_proxy:
        config.tor_proxy = args.tor_proxy
    if args.tor:
        config.tor_enabled = True
    if args.timeout:
        config.fetch_timeout_seconds = args.timeout
    if args.max_bytes:
        config.fetch_max_bytes = args.max_bytes

    try:
        result = run(
            args.url, config,
            offline=args.offline,
            no_fetch=args.no_fetch,
            no_external=args.no_external,
            no_cache=args.no_cache or args.refresh,
            no_store=args.no_store,
            cache_ttl_hours=args.cache_ttl,
            brands_path=args.brands,
        )
    except InvalidTargetError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(to_json(result))
    else:
        print(to_human_report(result, verbose=args.verbose, quiet=args.quiet))

    return 0


if __name__ == "__main__":
    sys.exit(main())
