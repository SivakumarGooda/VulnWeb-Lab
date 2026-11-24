"""The live OrbitDesk interface.

Every catalog entry is mounted at its realistic route. The shell around it
looks like a normal support SaaS so training agents have to discover the
features rather than read a menu of vulnerabilities.
"""
from __future__ import annotations

import json
from markupsafe import Markup
from flask import Blueprint, Response, render_template, request

import config
from . import auth, store
from .catalog import CATALOG
from . import product
from .handlers import make_view

bp = Blueprint("site", __name__)

for _vuln in CATALOG:
    bp.add_url_rule(
        _vuln.route,
        endpoint="vuln_" + _vuln.id.replace("-", "_"),
        view_func=make_view(_vuln),
        methods=["GET", "POST"],
    )


def _render(title: str, inner: str, status: int = 200):
    return render_template("site.html", v=None, title=title, content=Markup(inner)), status


@bp.get("/login")
def login_page():
    return _render("Sign in", product.login(next_=request.args.get("next", "")))


@bp.get("/dashboard")
def dashboard():
    user = auth.current_user() or {"name": "Alice"}
    return _render("Dashboard", product.dashboard(len(store.solved()), user["name"].split()[0]))


_PAGES = {
    "/tickets": ("Tickets", product.tickets),
    "/accounts": ("Accounts", product.accounts),
    "/billing": ("Billing", product.billing),
    "/files": ("Files", product.files),
    "/reports": ("Reports", product.reports),
    "/tools": ("Diagnostics", product.tools),
    "/integrations": ("Integrations", product.integrations),
    "/team": ("Team", product.team),
    "/admin": ("Admin", product.admin),
    "/account": ("Account", product.account),
    "/help-center": ("Help center", product.help_center),
    "/api-docs": ("API docs", product.api_docs),
}


def _page_view(title, builder):
    def view():
        return _render(title, builder())
    return view


for _path, (_title, _builder) in _PAGES.items():
    bp.add_url_rule(
        _path, endpoint="page_" + _path.strip("/").replace("-", "_"),
        view_func=_page_view(_title, _builder), methods=["GET"],
    )


@bp.get("/js/app.js")
def app_bundle():
    return Response(product.app_js(), mimetype="application/javascript")


@bp.get("/robots.txt")
def robots_txt():
    return Response(product.robots(request.host_url), mimetype="text/plain")


@bp.get("/sitemap.xml")
def sitemap_xml():
    return Response(product.sitemap(request.host_url), mimetype="application/xml")
