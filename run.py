#!/usr/bin/env python3
"""Run VulnWeb-Lab.

    python run.py            # learning mode: OrbitDesk + the Academy at /lab
    python run.py --exam     # exam mode: OrbitDesk only, no answers anywhere

Learning mode is for practising and following lessons. Exam mode is for
testing scanners and AI agents: the Academy, the catalog and the progress API
are hidden, and flags live in memory and change on every start.

Older commands still work: ``--mode both`` and ``--mode lab`` start learning
mode, ``--mode site`` starts exam mode.
"""
from __future__ import annotations

import argparse
import threading

from werkzeug.serving import make_server

import config
from app import create_app, resolve_mode
from app.catalog import counts
from app.mail import create_mail_app


def main() -> None:
    parser = argparse.ArgumentParser(
        description="VulnWeb-Lab - a deliberately vulnerable web app for learning and for testing tools"
    )
    parser.add_argument("--exam", action="store_true",
                        help="exam mode: OrbitDesk only, answers hidden, flags change every start")
    parser.add_argument("--host", default=config.HOST,
                        help=f"address to listen on (default {config.HOST})")
    parser.add_argument("--port", type=int, default=config.PORT,
                        help=f"port to listen on (default {config.PORT})")
    parser.add_argument("--mail-port", type=int, default=config.MAIL_PORT,
                        help=f"port for your mailbox (default {config.MAIL_PORT})")
    # Old mode names, kept so existing commands keep working.
    parser.add_argument("--mode", choices=("both", "lab", "site"), default="both",
                        help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.mode == "site" and not args.exam:
        print("Note: --mode site is now exam mode (use --exam).")
    config.MAIL_PORT = args.mail_port
    mode = resolve_mode(args.mode, args.exam)
    exam = mode == "exam"
    app = create_app(mode)
    counts_by_family = counts()
    total = sum(counts_by_family.values())

    print("=" * 72)
    print("  VulnWeb-Lab - deliberately vulnerable. Local training use only.")
    if exam:
        print("  Mode       : EXAM - OrbitDesk only, answers hidden")
    else:
        print("  Mode       : learning - OrbitDesk, plus the Academy at /lab")
    print(f"  Open       : http://{args.host}:{args.port}")
    print(f"  Mailbox    : http://{args.host}:{args.mail_port}  (mail for alice@orbitdesk.local and *@{config.INBOX_DOMAIN})")
    print("  Sign in    : alice@orbitdesk.local / alice123")
    print(f"  Contents   : {total} vulnerabilities across {len(counts_by_family)} types")
    print(f"  Flags      : {'change on every start, kept in memory' if exam else 'stay the same between restarts'}")
    print(f"  Safe mode  : {'ON (command execution and file reads off)' if config.SAFE_MODE else 'off'}")
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("  WARNING    : reachable from other machines - use an isolated network only.")
    else:
        print("  WARNING    : never expose this to the internet or a shared network.")
    print("=" * 72)

    mailbox = make_server(args.host, args.mail_port, create_mail_app(), threaded=True)
    threading.Thread(target=mailbox.serve_forever, daemon=True).start()
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
