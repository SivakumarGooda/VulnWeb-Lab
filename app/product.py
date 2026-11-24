"""OrbitDesk product pages: the navigable, realistic face of the range.

Features are placed where a real support SaaS would put them, with ordinary
product copy. Discovery is deliberately as uneven as on a real target:

* most features are reachable through the UI (links and forms);
* many API endpoints are only called from the single-page-app bundle
  (``/static/app.js``), some are only in the public developer docs;
* internal endpoints (debug, backups, logs, OAuth callbacks, legacy logins)
  are not linked at all; ``robots.txt`` leaks a few, like real sites do;
* ``sitemap.xml`` lists public pages only, never features;
* object IDs appear only for the signed-in user's own records.

Nothing here names a vulnerability, so exam mode stays a fair test.
"""

from __future__ import annotations

import html
from typing import Iterable

import config

from .catalog import CATALOG

# The signed-in user's own record id for each object API (IDOR routes): the
# record one below the foreign one. Only own ids are ever shown in the UI.
OWN_IDS = {
    v.route: int(v.extra["rid"]) - 1 for v in CATALOG if v.family == "idor"
}


def own(route: str) -> str:
    return route.replace("<int:rid>", str(OWN_IDS[route])).replace("<rid>", str(OWN_IDS[route]))


# ---------------------------------------------------------------------------
# Small HTML helpers
# ---------------------------------------------------------------------------

def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def a(href: str, text: str) -> str:
    return f'<a href="{esc(href)}">{esc(text)}</a>'


def gform(action: str, name: str, label: str, value: str = "", button: str = "Go",
          placeholder: str = "") -> str:
    return (
        f'<form class="inline" method="get" action="{esc(action)}">'
        f'<label>{esc(label)}</label>'
        f'<input name="{esc(name)}" value="{esc(value)}" placeholder="{esc(placeholder)}">'
        f'<button>{esc(button)}</button></form>'
    )


def pform(action: str, fields: Iterable[tuple], button: str, *, multipart: bool = False) -> str:
    """POST form. ``fields``: (name, label, kind, value) with kind text|textarea|hidden|file|email|number."""

    enctype = ' enctype="multipart/form-data"' if multipart else ""
    parts = [f'<form class="probe" method="post" action="{esc(action)}"{enctype}>']
    for name, label, kind, value in fields:
        if kind == "hidden":
            parts.append(f'<input type="hidden" name="{esc(name)}" value="{esc(value)}">')
            continue
        parts.append(f"<label>{esc(label)}</label>")
        if kind == "textarea":
            parts.append(f'<textarea name="{esc(name)}">{esc(value)}</textarea>')
        elif kind == "file":
            parts.append(f'<input type="file" name="{esc(name)}">')
        else:
            parts.append(f'<input type="{esc(kind)}" name="{esc(name)}" value="{esc(value)}">')
    parts.append(f"<button>{esc(button)}</button></form>")
    return "".join(parts)


def card(title: str, *body: str) -> str:
    return f'<article class="card"><h2>{esc(title)}</h2>{"".join(body)}</article>'


def ul(*items: str) -> str:
    return '<ul class="list">' + "".join(f"<li>{item}</li>" for item in items) + "</ul>"


def page(kicker: str, title: str, intro: str, *cards: str) -> str:
    return (
        f'<section class="panel"><p class="kicker">{esc(kicker)}</p><h1>{esc(title)}</h1>'
        f'<p class="muted">{esc(intro)}</p></section>'
        f'<section class="grid">{"".join(cards)}</section>'
    )


def upload(action: str, label: str, button: str = "Upload") -> str:
    return pform(action, [("file", label, "file", "")], button, multipart=True)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

def login(next_: str = "", error: str = "") -> str:
    error_html = f'<p class="bad">{esc(error)}</p>' if error else ""
    return (
        '<section class="panel narrow"><h1>Sign in to OrbitDesk</h1>'
        f"{error_html}"
        '<form class="probe" method="post" action="/auth/login">'
        '<label>Email</label><input name="email" autocomplete="username">'
        '<label>Password</label><input type="password" name="password" autocomplete="current-password">'
        '<label class="remember"><input type="checkbox" name="remember" value="1"> Keep me signed in</label>'
        f'<input type="hidden" name="next" value="{esc(next_)}">'
        "<button>Sign in</button></form>"
        '<p class="signin-links">' + a("/account/forgot-password", "Forgot password?")
        + " · " + a("/auth/magic-link", "Email me a sign-in link")
        + " · " + a("/auth/ldap", "Sign in with your company directory") + "</p>"
        "</section>"
    )


def dashboard(solved: int, name: str = "Alice") -> str:
    third = (
        '<div class="stat"><b>98%</b><span>SLA met</span></div>' if config.EXAM
        else f'<div class="stat"><b>{solved}</b><span>Flags captured</span></div>'
    )
    return (
        f'<section class="hero"><div><p class="kicker">Support operations</p><h1>Good morning, {esc(name)}</h1>'
        '<p class="muted">3 open tickets, 1 escalation, and 2 integrations need attention.</p></div>'
        '<div class="stat"><b>3</b><span>Open tickets</span></div>'
        f'<div class="stat"><b>1</b><span>Escalations</span></div>{third}</section>'
        '<section class="grid">'
        + card("Your tickets", '<ul class="list" data-api="tickets">'
               f'<li data-ticket-id="{OWN_IDS["/api/tickets/<int:rid>"]}">#1042 Printer on floor 3 is offline</li>'
               '<li>#1041 Quarterly access review</li></ul>', a("/tickets", "All tickets"))
        + card("Widgets", ul(a("/dashboard/widgets?widget=open-tickets", "Open tickets"),
                             a("/dashboard/widgets?widget=sla", "SLA"),
                             a("/widgets?name=workload", "Team workload")))
        + card("Notifications", ul(a("/notifications?id=12", "Escalation on #1042"),
                                   a("/notifications/preview?msg=Weekly digest", "Preview weekly digest"),
                                   a("/notifications/render?message=Your report is ready", "Report ready")))
        + card("Calendar", ul(a("/events?title=Quarterly review", "Quarterly review - Thu 10:00")))
        + card("Personalize", a("/dashboard/greeting?name=Alice", "Preview my greeting"))
        + card("Announcements", pform("/dashboard/announcements",
                                      [("content", "Post to the team", "textarea", "")], "Post"))
        + "</section>"
    )


def tickets() -> str:
    return page(
        "Workspace", "Tickets", "Every customer request, searchable and assignable.",
        card("Queue",
             '<table class="data"><tr><th>ID</th><th>Subject</th><th>Owner</th><th>State</th></tr>'
             f'<tr data-ticket-id="{OWN_IDS["/api/v1/tickets/<int:rid>"]}"><td>1042</td><td>Printer on floor 3 is offline</td><td>alice</td><td>open</td></tr>'
             '<tr><td>1041</td><td>Quarterly access review</td><td>bob</td><td>open</td></tr>'
             '<tr><td>1039</td><td>Invoice INV-2026-041</td><td>alice</td><td>closed</td></tr></table>',
             gform("/support/search", "q", "Search tickets", "", "Search")),
        card("Reply", pform("/tickets/comments", [("content", "Comment on #1042", "textarea", "")], "Comment"),
             pform("/support/reply", [("content", "Reply to the customer", "textarea", "")], "Send reply"),
             gform("/tickets/reply-template", "template", "Saved reply", "Thanks for reaching out", "Preview")),
        card("Customer details",
             gform("/support/avatar", "avatar_url", "Requester photo URL", "", "Fetch"),
             pform("/support/email", [("email", "Reply-to address", "email", ""),
                                      ("subject", "Subject", "text", "Escalate ticket #1042"),
                                      ("message", "Why does this need escalating?", "textarea", "")], "Escalate")),
        card("More", ul(a("/support?query=printer", "Search the support center"),
                        a("/support/redirect?url=/help/search", "Open in help center"),
                        a("/support/xml", "Import tickets from another system"),
                        a("/status/filter?state=open", "Filter by state"))),
    )


def accounts() -> str:
    return page(
        "Revenue", "Accounts", "Northwind Systems, Nexus Search, and 41 other accounts.",
        card("Find an account", gform("/customers", "q", "Account name", "", "Search"),
             '<table class="data"><tr><th>Account</th><th>Plan</th><th>Seats</th></tr>'
             '<tr><td>Northwind Systems</td><td>Enterprise</td><td>210</td></tr>'
             '<tr><td>Nexus Search</td><td>Growth</td><td>44</td></tr></table>'),
        card("Account notes", pform("/customers/notes", [("content", "Note on Nexus Search", "textarea", "")], "Save")),
    )


def billing() -> str:
    return page(
        "Billing", "Billing & plan", "Invoices, payments and your OrbitDesk subscription.",
        card("Invoices", ul(a("/billing/invoices?id=41", "INV-2026-041"),
                            a("/invoices/pdf?invoice=INV-2026-041", "Download PDF"),
                            a("/statements/download?file=2026-10.pdf", "October statement")),
             gform("/invoices/template", "template", "Invoice template", "default", "Preview")),
        card("Refunds", pform("/billing/refund", [("order_id", "Order", "text", ""), ("amount", "Amount", "number", "")], "Request refund")),
        card("Currency", pform("/billing/rounding", [("amount", "Amount to convert", "text", "10.00")], "Convert")),
        card("Shop", ul(a("/shop/products?category=hardware", "Hardware add-ons")),
             gform("/products", "name", "Find a product", "", "Search"),
             gform("/cart", "note", "Order note", "", "Save note"),
             pform("/cart/add", [("product", "", "hidden", "seat-pack"), ("qty", "Quantity", "number", "1")], "Add to cart")),
        card("Checkout",
             pform("/checkout/price", [("product", "", "hidden", "seat-pack"), ("price", "", "hidden", "129")], "Pay $129"),
             pform("/checkout/coupon", [("code", "Coupon", "text", ""), ("discount", "", "hidden", "10")], "Apply"),
             gform("/checkout/apply-coupon", "coupon", "Promo code", "", "Apply"),
             pform("/checkout/shipping", [("total", "", "hidden", "129"), ("shipping", "", "hidden", "15")], "Calculate shipping"),
             a("/billing/return?return_url=/billing", "Return to OrbitDesk")),
        card("Wallet",
             pform("/wallet/transfer", [("to", "Send to", "text", ""), ("amount", "Amount", "number", "")], "Transfer"),
             pform("/wallet/withdraw", [("amount", "Withdraw", "number", "")], "Withdraw"),
             pform("/payments/limit", [("amount", "Payment amount", "number", "")], "Pay"),
             pform("/gift/redeem", [("code", "Gift card", "text", "")], "Redeem")),
        card("Plan",
             pform("/trial/extend", [("days", "", "hidden", "14")], "Extend trial"),
             pform("/referrals/claim", [("email", "Your email", "email", ""), ("referrer", "Referred by", "email", "")], "Claim reward"),
             pform("/expenses/approve", [("requester", "", "hidden", "alice"), ("approver", "Approver", "text", "")], "Submit expense")),
        card("Orders", ul(a("/orders?id=1042", "Order 1042"), a("/orders/xml", "Bulk order import"))),
    )


def files() -> str:
    return page(
        "Workspace", "Files", "Shared attachments, exports and uploaded media.",
        card("Shared files",
             ul(f'welcome.txt {a("/files/download?file=welcome.txt", "download")} {a("/files/preview?file=welcome.txt", "preview")}',
                f'quarterly-report.txt {a("/files/download?file=quarterly-report.txt", "download")}',
                a("/uploads/get?filename=welcome.txt", "welcome.txt (original upload)")),
             gform("/files/search", "name", "Find a file", "", "Search"),
             pform("/files/description", [("content", "Description for welcome.txt", "textarea", "")], "Save")),
        card("Upload", upload("/files/upload", "Attachment"), upload("/media/upload", "Image or video"),
             upload("/documents/upload", "Document"), upload("/attachments/upload", "Ticket attachment"),
             upload("/files/upload-svg", "Logo (SVG)"), upload("/avatars/upload", "Profile photo"),
             upload("/files/upload-json", "Import from JSON", "Import"), upload("/imports/zip", "Import archive (.zip)", "Import"),
             upload("/templates/upload", "Email template", "Upload template")),
        card("Library", ul(a("/documents/view?doc=handbook.pdf", "Employee handbook"),
                           a("/attachments/get?id=report.txt", "Latest report attachment"),
                           a("/templates/view?name=welcome.html", "Welcome email template"),
                           a("/media/image?path=logo.png", "Brand logo"),
                           a("/certificates/download?name=orbitdesk.crt", "TLS certificate"),
                           a("/assets/file?name=brand.zip", "Brand kit"),
                           a("/archive/entry?path=2025/notes.txt", "2025 archive"),
                           a("/downloads?file=desktop-installer.exe", "Desktop app")),
             gform("/assets/search", "q", "Search assets", "", "Search"),
             f'<img src="/images/proxy?src=https://cdn.orbitdesk.example/logo.png" alt="logo" width="1" height="1">'),
        card("Exports",
             ul(a("/exports/download?path=tickets.csv", "tickets.csv"), a("/exports/preview?table=tickets", "Preview tickets export")),
             gform("/exports/csv/users", "name", "Export users named", "", "Export CSV"),
             gform("/exports/csv/tickets", "subject", "Export tickets with subject", "", "Export CSV"),
             gform("/exports/csv/audit", "note", "Export audit entries with note", "", "Export CSV"),
             gform("/exports/csv/invoices", "memo", "Export invoices with memo", "", "Export CSV"),
             gform("/exports/filename-template", "filename", "Export file name", "export-{date}", "Preview"),
             pform("/exports/all", [("scope", "", "hidden", "mine")], "Export all my data")),
        card("Share as PDF", gform("/pdf/render", "html_url", "Page to render", "https://app.orbitdesk.example/reports", "Render"),
             gform("/pdf/header", "header", "PDF header text", "OrbitDesk", "Preview"),
             gform("/screenshots", "url", "Screenshot a page", "", "Capture")),
    )


def reports() -> str:
    return page(
        "Analytics", "Reports", "Ticket volume, response times and SLA compliance.",
        card("Reports", ul("Ticket volume by week", "First response time", "SLA compliance",
                           a("/reports/view", "Executive summary"), a("/reports/hpp?scope=team", "Team scope")),
             gform("/reports/filter", "owner", "Filter by owner", "alice", "Filter")),
        card("Share", gform("/reports/share", "title", "Shared report title", "Weekly", "Share"),
             gform("/reports/title", "title", "Report heading", "Weekly", "Preview"),
             ul(a("/reports/download?name=weekly.csv", "Download weekly.csv"))),
        card("Import", gform("/reports/import", "source", "Import from URL", "", "Import"),
             a("/reports/xml", "Import a report definition")),
        card("Audit", gform("/audit/logs", "actor", "Activity by user", "alice", "Show")),
    )


def tools() -> str:
    diagnostics = [
        ("/tools/ping", "host", "Ping"), ("/tools/ping6", "host", "Ping (IPv6)"),
        ("/tools/dns", "host", "DNS lookup"), ("/tools/dig", "host", "DNS records"),
        ("/tools/host", "domain", "Host lookup"), ("/tools/whois", "domain", "Whois"),
        ("/tools/trace", "host", "Traceroute"), ("/tools/port", "host", "Port check"),
        ("/tools/tls", "host", "TLS handshake"), ("/tools/curl", "url", "HTTP check"),
        ("/tools/fetch", "url", "Fetch page"), ("/tools/git", "url", "Repository check"),
    ]
    files_tools = [
        ("/tools/convert", "file", "Convert image"), ("/tools/media", "file", "Inspect media file"),
        ("/tools/archive", "dir", "Archive folder"), ("/tools/zip", "dir", "Zip folder"),
    ]
    return page(
        "Admin tools", "Diagnostics", "Network and file utilities for workspace administrators.",
        card("Network", *(gform(action, name, label, "", "Run") for action, name, label in diagnostics)),
        card("Files", *(gform(action, name, label, "", "Run") for action, name, label in files_tools)),
        card("Previews", gform("/email/preview", "body", "Email body", "Hello {{customer}}", "Preview"),
             gform("/badges/print", "label", "Visitor badge", "Visitor", "Print")),
    )


def integrations() -> str:
    return page(
        "Integrations", "Integrations", "Connect OrbitDesk to the rest of your stack.",
        card("Webhooks", gform("/integrations/webhook/test", "url", "Send a test event to", "", "Test"),
             gform("/webhooks/deliver", "endpoint", "Redeliver to", "", "Redeliver")),
        card("Feeds & monitors", gform("/feeds/validate", "url", "Validate a feed", "", "Validate"),
             gform("/rss/preview", "feed", "Preview RSS", "", "Preview"),
             gform("/monitor/check", "url", "Uptime check", "", "Check")),
        card("Directory", gform("/integrations/search", "q", "Find an integration", "", "Search"),
             a("/integrations/xml", "Import configuration")),
        card("Sign-in providers", ul(
            a("/oauth/authorize?redirect_uri=https://app.orbitdesk.example/sso/callback", "Connect Google Workspace"),
            a("/app/launch?target=/dashboard", "Open OrbitDesk launcher"))),
    )


def team() -> str:
    return page(
        "People", "Team", "Your support team and company directory.",
        card("Members", gform("/team/members", "q", "Find a teammate", "", "Search"),
             gform("/directory/search", "filter", "Company directory", "", "Look up"),
             gform("/staff/search", "filter", "Staff directory", "", "Look up")),
        card("Invite", gform("/invite", "email", "Invite by email", "", "Invite"),
             gform("/team/invite", "name", "Teammate name", "", "Continue"),
             pform("/invite/send", [("email", "Invite by email", "email", "")], "Send invitation"),
             pform("/invite/email", [("email", "Your email", "email", ""), ("subject", "Request", "text", "Extra seat for a new hire")], "Ask IT for a seat"),
             pform("/invitations", [("content", "Personal message", "textarea", "")], "Save message"),
             ul(a("/invite/send?email=bob@orbitdesk.local", "Resend Bob's invitation"),
                a("/invite/accept?next=/dashboard", "Preview the acceptance page"),
                a("/welcome/preview?name=Bob", "Preview welcome screen"))),
    )


def admin() -> str:
    return page(
        "Administration", "Admin", "User management, roles, audit log and workspace settings.",
        card("Users", gform("/admin/users", "q", "Find a user", "a", "Search"),
             pform("/admin/role", [("email", "User", "email", ""), ("role", "Role", "text", "agent")], "Change role"),
             ul(a("/admin/panel", "Workspace settings"), a("/admin/impersonate", "Sign in as a user"),
                a("/admin/redirect?url=/dashboard", "Open user's workspace"),
                a("/admin/filter-hpp?status=pending", "Pending approvals"))),
        card("Audit", gform("/admin/audit", "note", "Annotate audit log", "review", "Save"),
             pform("/workflow/approve", [("request", "", "hidden", "1042"), ("status", "", "hidden", "pending")], "Send for approval")),
        card("Maintenance", gform("/admin/url-check", "url", "Check a URL", "", "Check"),
             ul(a("/backup/download?file=nightly.tar.gz", "Latest nightly backup"),
                a("/logs/view?file=app.log", "Application log")),
             gform("/backup/remote", "remote", "Copy backups to", "", "Copy"),
             upload("/backups/upload", "Restore from backup", "Restore")),
    )


def account() -> str:
    return page(
        "Personal", "Account", "Alice Chen · alice@orbitdesk.local · Support Engineer",
        card("Profile", gform("/profile", "name", "Display name", "Alice Chen", "Preview"),
             pform("/profile/bio", [("content", "About me", "textarea", "")], "Save bio"),
             pform("/account/update", [("name", "Name", "text", "Alice Chen"), ("email", "Email", "email", "alice@orbitdesk.local")], "Update")),
        card("Settings", ul(a("/settings?tab=notifications", "Notifications"), a("/account/settings", "Preferences"),
                            a("/account/security", "Security"), a("/account/remember", "Remember this device")),
             pform("/account/email", [("email", "New email", "email", "")], "Change email"),
             pform("/account/reset", [("email", "Send me a reset link", "email", "alice@orbitdesk.local")], "Reset password")),
        card("Email signature", pform("/signature", [("content", "Signature", "textarea", "")], "Save"),
             gform("/signature/preview", "signature", "Preview signature", "Alice | OrbitDesk", "Preview")),
        card("Language", ul(a("/i18n/set?value=en", "English"), a("/i18n/set?value=es", "Español"),
                            a("/i18n/set?value=ko", "한국어"))),
        card("Session", ul(a("/auth/continue?return_to=/dashboard", "Continue where I left off"),
                           a("/login/redirect?next=/dashboard", "Switch workspace"),
                           a("/logout?redirect=/login", "Sign out"))),
    )


def help_center() -> str:
    return page(
        "Help", "Help center", "Guides, community answers and product updates.",
        card("Search", gform("/help/search", "q", "Search help", "", "Search"),
             gform("/knowledge/search", "q", "Search articles", "", "Search"),
             a("/search/advanced?q=", "Advanced search")),
        card("Popular", ul(a("/knowledge/article?q=sla", "Understanding SLAs"),
                           a("/docs?page=getting-started", "Getting started"),
                           a("/docs/redirect?to=https://github.com/orbitdesk", "OrbitDesk on GitHub"),
                           a("/blog?slug=release-notes", "Release notes"),
                           a("/status", "System status"))),
        card("Was this helpful?", pform("/knowledge/feedback", [("content", "Tell us more", "textarea", "")], "Send"),
             gform("/feedback", "text", "Quick feedback", "", "Send"),
             gform("/comments", "text", "Preview a community comment", "", "Preview")),
        card("Community", pform("/wiki", [("content", "Edit the team wiki", "textarea", "")], "Save page"),
             pform("/reviews", [("content", "Write a review", "textarea", "")], "Post review"),
             pform("/status/update", [("content", "Status update", "textarea", "")], "Publish")),
        card("Contact us", pform("/contact", [("email", "Your email", "email", ""), ("subject", "Subject", "text", ""),
                                              ("message", "Message", "textarea", "")], "Send")),
        card("Other sign-in options", ul(a("/auth/demo/login", "Try the demo workspace"),
                                         a("/auth/support/login", "Partner portal"),
                                         a("/auth/staff", "Staff sign-in"))),
    )


# ---------------------------------------------------------------------------
# Public developer docs: the documented subset of the API
# ---------------------------------------------------------------------------

DOCUMENTED_API = (
    ("GET", "/api/v1/tickets/search", "q", "Search tickets"),
    ("GET", "/api/v2/tickets", "q", "List tickets (v2)"),
    ("GET", "/api/v1/tickets/{id}", "", "Ticket detail"),
    ("GET", "/api/v1/invoices/{id}", "", "Invoice detail"),
    ("GET", "/api/v3/orders", "ref", "Find orders by reference"),
    ("GET", "/api/v1/me", "", "Current user (Bearer token)"),
    ("GET", "/api/token/verify", "", "Validate a token (Bearer token)"),
    ("POST", "/api/login", "username, password (JSON)", "Sign in"),
    ("POST", "/api/v2/login", "username, password (JSON)", "Sign in (v2)"),
    ("POST", "/api/search", "JSON query", "Search records"),
    ("GET", "/api/preview", "q", "Rich-text preview"),
    ("GET", "/api/link-preview", "url", "Unfurl a link"),
    ("GET", "/api/directory", "filter", "Directory lookup"),
    ("POST", "/api/xml/import", "XML body", "Import records"),
    ("POST", "/api/email/send", "email, subject", "Send a notification email"),
    ("GET", "/api/password-reset", "", "Start a password reset"),
    ("GET", "/api/v1/export", "", "Export workspace data"),
    ("GET", "/api/billing", "", "Billing summary"),
    ("GET", "/api/account/profile", "", "Profile"),
)


def api_docs() -> str:
    rows = "".join(
        f"<tr><td>{esc(m)}</td><td><code>{esc(p)}</code></td><td>{esc(params)}</td><td>{esc(purpose)}</td></tr>"
        for m, p, params, purpose in DOCUMENTED_API
    )
    return (
        '<section class="panel"><p class="kicker">Developers</p><h1>OrbitDesk API</h1>'
        '<p class="muted">REST and JSON endpoints used by the web app, mobile clients and integrations. '
        "Authenticate with <code>Authorization: Bearer &lt;token&gt;</code>.</p>"
        f'<table class="data"><tr><th>Method</th><th>Path</th><th>Parameters</th><th>Purpose</th></tr>{rows}</table></section>'
    )


# ---------------------------------------------------------------------------
# robots.txt and sitemap.xml
# ---------------------------------------------------------------------------

def robots(base: str) -> str:
    # Real robots files often leak private paths while trying to hide them.
    return (
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /debug/\n"
        "Disallow: /logs/\n"
        "Disallow: /soap/\n"
        "Disallow: /internal/\n"
        "Disallow: /auth/login-legacy\n"
        f"Sitemap: {base.rstrip('/')}/sitemap.xml\n"
    )


PUBLIC_PAGES = (
    "/login", "/help-center", "/docs?page=getting-started", "/blog?slug=release-notes",
    "/status", "/api-docs", "/shop/products?category=hardware",
)


def sitemap(base: str) -> str:
    root = base.rstrip("/")
    urls = "".join(f"<url><loc>{esc(root + path)}</loc></url>" for path in PUBLIC_PAGES)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>'
    )


def app_js() -> str:
    """The SPA bundle, bootstrapped with the signed-in user's own record ids."""

    import json
    from pathlib import Path

    me = {
        "user": OWN_IDS["/api/users/<int:rid>"],
        "invoice": OWN_IDS["/api/invoices/<int:rid>"],
        "subscription": OWN_IDS["/api/subscriptions/<int:rid>"],
        "note": OWN_IDS["/api/notes/<int:rid>"],
    }
    template = (Path(__file__).parent / "templates" / "app.js").read_text(encoding="utf-8")
    return template.replace("__ORBIT_ME__", json.dumps(me))


NAV = (
    ("/dashboard", "Dashboard"), ("/tickets", "Tickets"), ("/accounts", "Accounts"),
    ("/billing", "Billing"), ("/files", "Files"), ("/reports", "Reports"), ("/team", "Team"),
    ("/integrations", "Integrations"), ("/tools", "Tools"), ("/admin", "Admin"),
    ("/help-center", "Help"), ("/api-docs", "API"),
)
