"""Accounts, sessions and the sign-in wall.

OrbitDesk has real sign-in: a session cookie, pages that send you to /login
when you are signed out, and API endpoints that answer 401. Public pages (the
sign-in flows, the help center, the API docs, a few leaky files) stay open,
like on a real product.

Accounts:

* ``alice@orbitdesk.local`` / ``alice123``: the tester's own account. Her mail
  arrives in the tester's mailbox.
* ``bob@orbitdesk.local`` / ``bob123``: a colleague whose password the tester
  knows, but whose account has two-step verification. Bob's mail is not
  visible.
* ``admin@orbitdesk.local``: the administrator, with a strong random password.
"""
from __future__ import annotations

import base64
import re
import secrets
from urllib.parse import quote

from flask import jsonify, redirect, request, session

from . import store
from .catalog import CATALOG

TESTER = "alice@orbitdesk.local"
NAMES = {
    "admin@orbitdesk.local": "Workspace Admin",
    "alice@orbitdesk.local": "Alice Chen",
    "bob@orbitdesk.local": "Bob Park",
}
TWO_FACTOR = {"bob@orbitdesk.local"}

PASSWORDS: dict[str, str] = {}      # passwords changed through a reset
API_TOKENS: dict[str, str] = {}     # bearer token -> email
LINK_TOKENS: dict[str, dict] = {}   # emailed link token -> {purpose, email, vuln}
CODES: dict[str, str] = {}          # email -> current emailed code


# ---------------------------------------------------------------------------
# Accounts
# ---------------------------------------------------------------------------

def account(email: str) -> dict | None:
    email = (email or "").strip().lower()
    if "@" not in email:
        email = f"{email}@orbitdesk.local"
    for uid, address, _password, role in store.USERS:
        if address == email:
            return {"id": uid, "email": address, "role": role,
                    "name": NAMES.get(address, address.split("@")[0].title())}
    return None


def check_password(email: str, password: str) -> dict | None:
    found = account(email)
    if not found:
        return None
    stored = PASSWORDS.get(found["email"])
    if stored is None:
        stored = next(pw for _uid, address, pw, _role in store.USERS if address == found["email"])
    return found if secrets.compare_digest(str(password or ""), stored) else None


def set_password(email: str, password: str) -> None:
    PASSWORDS[email.lower()] = password


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

def current_user() -> dict | None:
    email = session.get("user")
    if not email:
        return None
    found = account(email) or {"email": email, "name": email, "role": "user"}
    return {**found, "role": session.get("role", found["role"])}


def sign_in(email: str, role: str | None = None) -> None:
    found = account(email)
    session.clear()
    session["user"] = found["email"] if found else email
    session["role"] = role or (found["role"] if found else "user")


def sign_out() -> None:
    session.clear()


def safe_next(value: str | None, default: str = "/dashboard") -> str:
    value = value or ""
    if value.startswith("/") and not value.startswith("//") and "\\" not in value:
        return value
    return default


def issue_link(purpose: str, email: str, vuln_id: str) -> str:
    token = secrets.token_urlsafe(18)
    LINK_TOKENS[token] = {"purpose": purpose, "email": email.lower(), "vuln": vuln_id}
    return token


def redeem_link(token: str, purpose: str) -> dict | None:
    record = LINK_TOKENS.get(token or "")
    if record and record["purpose"] == purpose:
        return LINK_TOKENS.pop(token)
    return None


def issue_code(email: str) -> str:
    code = f"{secrets.randbelow(900000) + 100000}"
    CODES[email.lower()] = code
    return code


def issue_api_token(email: str) -> str:
    token = secrets.token_urlsafe(24)
    API_TOKENS[token] = email
    return token


def remember_cookie(email: str, role: str) -> str:
    return base64.b64encode(f"{email}:{role}".encode()).decode()


def from_remember_cookie(raw: str) -> tuple[str, str] | None:
    try:
        email, _, role = base64.b64decode(raw or "").decode("utf-8").partition(":")
    except Exception:
        return None
    found = account(email) if email else None
    return (found["email"], role or found["role"]) if found else None


# ---------------------------------------------------------------------------
# The sign-in wall
# ---------------------------------------------------------------------------

#: Pages a visitor can open while signed out.
PUBLIC_PAGES = {
    "/", "/login", "/help-center", "/api-docs", "/robots.txt", "/sitemap.xml",
    "/js/app.js", "/health", "/api/verify", "/api/catalog", "/api/solves",
}

#: Features that live outside the signed-in app: sign-in, reset and token
#: flows, the public contact form, redirects and caches in front of the app.
PUBLIC_PREFIXES = (
    "/auth/", "/account/forgot-password", "/account/reset", "/account/remember",
    "/api/token/", "/api/v1/me", "/api/login", "/api/v2/login", "/api/password-reset",
    "/contact", "/invite/send",
)
PUBLIC_FAMILIES = {"redirect", "cache"}

_HREF = re.compile(r'(?:href|action)="(/[^"#?]*)')
_PUBLIC: set[str] | None = None


def public_rules() -> set[str]:
    global _PUBLIC
    if _PUBLIC is None:
        from . import product

        rules = set(PUBLIC_PAGES)
        # everything linked from the public pages: sign-in, help center, sitemap
        for page in (product.login(), product.help_center()):
            rules.update(_HREF.findall(page))
        rules.update(path.split("?")[0] for path in product.PUBLIC_PAGES)
        for vuln in CATALOG:
            if vuln.family in PUBLIC_FAMILIES or vuln.route.startswith(PUBLIC_PREFIXES):
                rules.add(vuln.route)
            elif vuln.family == "info" and not vuln.route.startswith(("/account", "/api/account")):
                rules.add(vuln.route)  # leaked files and debug pages sit outside the app
        _PUBLIC = rules
    return _PUBLIC


def requires_login(rule: str) -> bool:
    return rule not in public_rules()


def _bearer() -> str:
    raw = request.headers.get("Authorization", "")
    return raw[7:].strip() if raw.lower().startswith("bearer ") else ""


def gate():
    """``before_request``: send signed-out visitors to the sign-in page."""

    rule = request.url_rule
    if rule is None or request.endpoint == "static" or rule.rule.startswith("/lab"):
        return None
    if not requires_login(rule.rule) or session.get("user"):
        return None
    restored = from_remember_cookie(request.cookies.get("remember", ""))
    if restored:
        sign_in(*restored)
        return None
    if _bearer() in API_TOKENS:
        return None
    if request.path.startswith("/api/"):
        return jsonify({"error": "authentication required"}), 401
    target = request.full_path.rstrip("?")
    return redirect("/login?next=" + quote(target, safe="/"))
