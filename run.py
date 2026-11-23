#!/usr/bin/env python3
"""Run VulnWeb-Lab.

    python run.py --mode both              # guided: OrbitDesk + Academy
    python run.py --mode site              # OrbitDesk only
    python run.py --mode lab               # Academy (site endpoints still targets)
    python run.py --exam                   # exam: OrbitDesk only, no answers anywhere

Modes:
    site  - only the realistic OrbitDesk interface
    lab   - guided Academy; the live endpoints remain available as targets
    both  - OrbitDesk at / and Academy at /lab (default)

Exam mode (``--exam`` or ``RANGE_EXAM=1``) hides the Academy, the catalog and
the progress API, keeps flags in memory only, and rotates them every start.
"""
from __future__ import annotations

import argparse

from app import create_app
from app.catalog import counts
import config


def main() -> None:
    parser = argparse.ArgumentParser(description="VulnWeb-Lab - intentionally vulnerable web range")
    parser.add_argument("--mode", choices=("site", "lab", "both"), default="both")
    parser.add_argument("--exam", action="store_true",
                        help="exam mode: no Academy, no catalog, in-memory rotating flags")
    parser.add_argument("--host", default=config.HOST)
    parser.add_argument("--port", type=int, default=config.PORT)
    args = parser.parse_args()

    exam = args.exam or config.EXAM
    app = create_app(args.mode, exam=exam)
    counts_by_family = counts()
    total = sum(counts_by_family.values())
    interface = "OrbitDesk only (exam)" if exam else (
        "OrbitDesk at / and Academy at /lab" if args.mode == "both" else args.mode
    )

    print("=" * 72)
    print("  VulnWeb-Lab - deliberately vulnerable. Local training use only.")
    print(f"  Interfaces : {interface}")
    print(f"  Listening  : http://{args.host}:{args.port}")
    print(f"  Catalog    : {total} vulnerabilities across {len(counts_by_family)} families")
    print(f"  Flags      : {'rotated per start, memory only (exam)' if exam else 'stable per instance secret (guided)'}")
    print(f"  Safe mode  : {'ON (RCE/file reads disabled)' if config.SAFE_MODE else 'off'}")
    print(f"  Instance   : {config.INSTANCE_DIR}")
    print("  WARNING    : never bind this to a public interface or shared network.")
    print("=" * 72)

    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
