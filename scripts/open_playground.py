#!/usr/bin/env python3
"""Print or open the hosted Silmaril Firewall demo for Hermes Firewall."""

from __future__ import annotations

import argparse
import json
import os
import sys
import webbrowser
from typing import Any
from urllib.parse import urljoin


DEFAULT_DEMO_BASE_URL = "https://app.silmaril.dev"
ROUTES = {
    "setup": "/demo/setup-complete",
    "playground": "/demo/playground",
}


def normalize_base_url(value: str | None) -> str:
    raw = (value or DEFAULT_DEMO_BASE_URL).strip()
    if raw.startswith(("http://", "https://")):
        return raw
    return f"https://{raw}"


def normalize_route(value: str | None) -> str:
    return "playground" if value == "playground" else "setup"


def build_demo_url(base_url: str | None = None, route: str | None = "setup") -> str:
    normalized = normalize_base_url(base_url)
    if not normalized.endswith("/"):
        normalized = f"{normalized}/"
    return urljoin(normalized, ROUTES[normalize_route(route)].lstrip("/"))


def resolve_runtime_config(env: dict[str, str] | None = None) -> dict[str, Any]:
    source = os.environ if env is None else env
    api_url = _read_string(source.get("SILMARIL_API_URL"))
    api_key = _read_string(source.get("SILMARIL_API_KEY"))
    return {
        "configured": bool(api_url and api_key),
        "apiUrl": api_url,
        "hasApiKey": bool(api_key),
    }


def _read_string(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Print or open the public Silmaril Firewall demo URL.",
    )
    parser.add_argument("--open", action="store_true", help="Open the URL with the system browser.")
    parser.add_argument("--json", action="store_true", help="Print JSON status instead of a bare URL.")
    parser.add_argument("--playground", action="store_true", help="Open the playground route.")
    parser.add_argument("--route", choices=("setup", "playground"), default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    route = "playground" if args.playground else normalize_route(args.route)
    url = build_demo_url(os.getenv("SILMARIL_DEMO_BASE_URL"), route)
    config = resolve_runtime_config()

    if args.json:
        print(json.dumps({"url": url, **config}, sort_keys=True))
    else:
        print(url)

    if args.open:
        webbrowser.open(url, new=2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
