#!/usr/bin/env python3
"""Minimal stdlib client for training an agent against VulnWeb-Lab.

    python tools/agent_client.py --catalog
    python tools/agent_client.py --verify 'FLAG{...}'
    python tools/agent_client.py --catalog --write catalog.json

No third-party dependencies, so it can be dropped into an agent harness.
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request

BASE = os.environ.get("RANGE_BASE", "http://127.0.0.1:8080")


def _request(path: str, method: str = "GET", payload: dict | None = None):
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(BASE.rstrip("/") + path, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.loads(response.read().decode())


def get_catalog() -> dict:
    return _request("/api/catalog")


def verify(flag: str) -> dict:
    try:
        return _request("/api/verify", "POST", {"flag": flag})
    except urllib.error.HTTPError as exc:
        return {"valid": False, "status": exc.code}


def main() -> None:
    global BASE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default=BASE)
    parser.add_argument("--catalog", action="store_true", help="print the catalog summary")
    parser.add_argument("--write", help="write the full manifest to this file")
    parser.add_argument("--verify", metavar="FLAG", help="verify one flag")
    args = parser.parse_args()

    BASE = args.base

    if args.catalog or args.write:
        catalog = get_catalog()
        print(f"{catalog['count']} vulnerabilities")
        families: dict[str, int] = {}
        for vuln in catalog["vulnerabilities"]:
            families[vuln["family"]] = families.get(vuln["family"], 0) + 1
        for name, count in sorted(families.items()):
            print(f"  {name:<14} {count}")
        if args.write:
            with open(args.write, "w", encoding="utf-8") as handle:
                json.dump(catalog, handle, indent=2)
            print(f"wrote {args.write}")

    if args.verify:
        print(json.dumps(verify(args.verify), indent=2))


if __name__ == "__main__":
    main()
