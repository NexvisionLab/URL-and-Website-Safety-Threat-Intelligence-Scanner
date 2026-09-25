#!/usr/bin/env python3
"""Generate a shareable report from one or more URL investigations.

Usage:
    python report.py <url> [<url2> ...]        # investigate (or reuse cache) and report
    python report.py --all                     # report on everything already in the cache
    python report.py --all --since 24          # only entries checked in the last 24 hours
    python report.py <url> --format html -o report.html
"""
import argparse
import sys
from pathlib import Path

from usi import cache
from usi.config import load_config
from usi.output.formatter import result_from_dict
from usi.output.report import build_html, build_markdown
from usi.pipeline import InvalidTargetError, run


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="report.py",
        description="Generate a shareable Markdown or HTML report from URL investigations, "
                     "either freshly run or pulled from the local cache.",
    )
    p.add_argument("urls", nargs="*", help="URL(s) to investigate and report on")
    p.add_argument("--all", action="store_true",
                    help="Report on every investigation already in the cache, instead of a URL list")
    p.add_argument("--since", type=float, metavar="HOURS",
                    help="With --all, only include entries checked within this many hours")
    p.add_argument("--refresh", action="store_true",
                    help="Force a fresh investigation even if a cached result exists (ignored with --all)")
    p.add_argument("--format", choices=["md", "html"], default="md", help="Report format (default: md)")
    p.add_argument("-o", "--output", type=Path, help="Output file path (default: auto-generated)")
    p.add_argument("--title", default="URL Safety Investigation Report", help="Report title")
    p.add_argument("--config", type=Path, help="Path to config.toml")
    return p


def main(argv=None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    args = build_parser().parse_args(argv)

    if not args.all and not args.urls:
        print("Provide one or more URLs, or use --all to report on the cache. See --help.", file=sys.stderr)
        return 2
    if args.all and args.urls:
        print("--all and a URL list are mutually exclusive.", file=sys.stderr)
        return 2

    config = load_config(args.config)

    if args.all:
        cached_dicts = cache.list_all(config.cache_path, since_hours=args.since)
        if not cached_dicts:
            print("No cached investigations found" +
                  (f" in the last {args.since}h." if args.since else "."), file=sys.stderr)
            return 1
        results = [result_from_dict(d) for d in cached_dicts]
    else:
        results = []
        for url in args.urls:
            try:
                results.append(run(url, config, no_cache=args.refresh))
            except InvalidTargetError as e:
                print(f"skipping {url!r}: {e}", file=sys.stderr)
        if not results:
            print("No valid URLs to report on.", file=sys.stderr)
            return 2

    if args.format == "html":
        content = build_html(results, title=args.title)
        default_ext = "html"
    else:
        content = build_markdown(results, title=args.title)
        default_ext = "md"

    output_path = args.output or Path(f"report.{default_ext}")
    output_path.write_text(content, encoding="utf-8")
    print(f"Report written to {output_path} ({len(results)} URL(s)).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
