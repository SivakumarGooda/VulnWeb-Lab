"""Outgoing mail, and the tester's mailbox server.

OrbitDesk sends real-looking mail (password resets, sign-in links, one-time
codes, invitations, contact-form copies). Nothing leaves the process: every
message is kept in memory.

The tester owns two kinds of address, and only their mail is visible:

* their OrbitDesk account, ``alice@orbitdesk.local``;
* any address at ``@inbox.test``, their own outside mail domain.

Everyone else (the admin, Bob, customers) is a victim: their mail is never
shown. Like a real victim, they click the links in their mail. When a link
points at a host the tester controls (the mailbox server's port, or any
``*.inbox.test`` host), the visit shows up in the mailbox's request log, just
as it would in a real attacker's web server log.

The mailbox server runs on its own port (``RANGE_MAIL_PORT``, default 8025).
"""
from __future__ import annotations

import html
import re
import threading
from datetime import datetime, timezone
from urllib.parse import urlsplit

from flask import Flask, Response, abort, jsonify, request

import config

MESSAGES: list[dict] = []
REQUESTS: list[dict] = []
_LOCK = threading.Lock()

SENDER = "OrbitDesk <no-reply@orbitdesk.local>"
URL = re.compile(r"https?://[^\s\"'<>]+")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _address(value: str) -> str:
    match = re.search(r"<([^>]+)>", value)
    return (match.group(1) if match else value).strip().lower()


def is_tester_address(value: str) -> bool:
    address = _address(value)
    return address == config.TESTER_EMAIL or address.endswith("@" + config.INBOX_DOMAIN)


def is_tester_host(netloc: str) -> bool:
    netloc = netloc.lower().rsplit("@", 1)[-1]
    name, _, port = netloc.partition(":")
    domain = config.INBOX_DOMAIN
    return name == domain or name.endswith("." + domain) or port == str(config.MAIL_PORT)


def headers(to: str, subject: str, *, sender: str = SENDER, extra: str = "") -> str:
    """The raw header block a simple mailer builds by joining strings."""

    block = f"From: {sender}\r\nTo: {to}\r\nSubject: {subject}\r\n"
    return block + (extra + "\r\n" if extra else "")


def send(raw_headers: str, body: str) -> list[str]:
    """Deliver a message to every To, Cc and Bcc recipient in the header block."""

    parsed: list[tuple[str, str]] = []
    for line in re.split(r"\r\n|\r|\n", raw_headers):
        if ":" in line:
            name, value = line.split(":", 1)
            parsed.append((name.strip(), value.strip()))

    recipients: list[str] = []
    for name, value in parsed:
        if name.lower() in ("to", "cc", "bcc"):
            recipients += [part.strip() for part in value.split(",") if part.strip()]

    subject = next((value for name, value in parsed if name.lower() == "subject"), "")
    shown = [(name, value) for name, value in parsed if name.lower() != "bcc"]
    with _LOCK:
        for recipient in recipients:
            message = {
                "id": len(MESSAGES) + 1,
                "date": _now(),
                "to": _address(recipient),
                "subject": subject,
                "headers": shown,
                "body": body,
            }
            MESSAGES.append(message)
            if not is_tester_address(recipient):
                _victim_opens(message)
    return recipients


def send_simple(to: str, subject: str, body: str) -> None:
    send(headers(to, subject), body)


def _victim_opens(message: dict) -> None:
    """A victim opens the mail and clicks its links (caller holds the lock)."""

    for url in URL.findall(message["body"]):
        parts = urlsplit(url)
        if is_tester_host(parts.netloc):
            REQUESTS.append({
                "id": len(REQUESTS) + 1,
                "date": _now(),
                "method": "GET",
                "host": parts.netloc,
                "path": parts.path + (f"?{parts.query}" if parts.query else ""),
                "client": f"{message['to']} (mail client)",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OrbitMail-Preview",
            })


def inbox() -> list[dict]:
    with _LOCK:
        return [dict(m) for m in MESSAGES if is_tester_address(m["to"])]


def requests_log() -> list[dict]:
    with _LOCK:
        return [dict(r) for r in REQUESTS]


def clear() -> None:
    with _LOCK:
        MESSAGES[:] = [m for m in MESSAGES if not is_tester_address(m["to"])]
        REQUESTS.clear()


# ---------------------------------------------------------------------------
# The mailbox server
# ---------------------------------------------------------------------------

_STYLE = """
:root{--bg:#f6f7f9;--fg:#1d2330;--muted:#667085;--line:#e3e6eb;--card:#fff;--accent:#2563eb}
@media (prefers-color-scheme: dark){:root{--bg:#0f141b;--fg:#e6e9ef;--muted:#98a2b3;--line:#273041;--card:#161d27;--accent:#60a5fa}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif}
header{padding:16px 24px;border-bottom:1px solid var(--line);display:flex;gap:24px;align-items:center;flex-wrap:wrap}
header b{font-size:17px}header a{color:var(--accent);text-decoration:none}main{max-width:960px;margin:0 auto;padding:16px}
.muted{color:var(--muted)}table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line)}
td,th{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:13px;color:var(--muted)}
pre{white-space:pre-wrap;word-break:break-all;background:var(--card);border:1px solid var(--line);padding:12px}
a{color:var(--accent)}button{font:inherit;padding:4px 12px}
"""


def _layout(title: str, inner: str) -> Response:
    page = (
        f"<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{html.escape(title)} · Mailbox</title><style>{_STYLE}</style></head><body>"
        "<header><b>Mailbox</b><a href='/'>Inbox</a><a href='/requests'>Requests</a>"
        f"<span class='muted'>Mail for {html.escape(config.TESTER_EMAIL)} and any address "
        f"@{html.escape(config.INBOX_DOMAIN)}</span></header><main>{inner}</main></body></html>"
    )
    return Response(page, mimetype="text/html")


def create_mail_app() -> Flask:
    app = Flask("mailbox")

    @app.get("/")
    def index():
        rows = "".join(
            f"<tr><td>{html.escape(m['date'])}</td><td>{html.escape(m['to'])}</td>"
            f"<td><a href='/message/{m['id']}'>{html.escape(m['subject'] or '(no subject)')}</a></td></tr>"
            for m in reversed(inbox())
        ) or "<tr><td colspan='3' class='muted'>No mail yet.</td></tr>"
        return _layout("Inbox", (
            "<h1>Inbox</h1><form method='post' action='/clear'><button>Clear mailbox</button></form><br>"
            f"<table><tr><th>Received</th><th>To</th><th>Subject</th></tr>{rows}</table>"
        ))

    @app.get("/message/<int:message_id>")
    def message(message_id: int):
        found = next((m for m in inbox() if m["id"] == message_id), None)
        if found is None:
            abort(404)
        head = "\n".join(f"{name}: {value}" for name, value in found["headers"])
        body = URL.sub(lambda m: f"<a href='{html.escape(m.group(0))}'>{html.escape(m.group(0))}</a>",
                       html.escape(found["body"]))
        return _layout(found["subject"], (
            f"<h1>{html.escape(found['subject'])}</h1><pre>{html.escape(head)}</pre><pre>{body}</pre>"
        ))

    @app.get("/requests")
    def requests_page():
        rows = "".join(
            f"<tr><td>{html.escape(r['date'])}</td><td>{html.escape(r['method'])}</td>"
            f"<td>{html.escape(r['host'] + r['path'])}</td><td>{html.escape(r['client'])}</td></tr>"
            for r in reversed(requests_log())
        ) or "<tr><td colspan='4' class='muted'>No requests yet.</td></tr>"
        return _layout("Requests", (
            "<h1>Requests to your server</h1>"
            f"<p class='muted'>Any request to this server, or to a link pointing at a *.{html.escape(config.INBOX_DOMAIN)} host, appears here.</p>"
            f"<table><tr><th>Time</th><th>Method</th><th>URL</th><th>From</th></tr>{rows}</table>"
        ))

    @app.get("/api/messages")
    def api_messages():
        return jsonify(inbox())

    @app.get("/api/requests")
    def api_requests():
        return jsonify(requests_log())

    @app.post("/clear")
    def clear_view():
        clear()
        return Response("", 303, {"Location": "/"})

    @app.route("/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    def catch_all(path: str):
        # Anything else is "your web server": log it, like an attacker-controlled host.
        with _LOCK:
            REQUESTS.append({
                "id": len(REQUESTS) + 1,
                "date": _now(),
                "method": request.method,
                "host": request.host,
                "path": request.full_path.rstrip("?"),
                "client": request.remote_addr or "",
                "user_agent": request.headers.get("User-Agent", ""),
            })
        return Response("OK\n", mimetype="text/plain")

    return app
