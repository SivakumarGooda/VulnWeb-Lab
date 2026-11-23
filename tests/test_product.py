"""OrbitDesk product realism: navigation, hidden internals, own-only IDs, no hints.

These guard the design rule that the site is built like a real product, not
for the scanner: features are linked where a real SaaS links them, internal
endpoints stay unlinked, object IDs are only the signed-in user's own, and no
page names a vulnerability.
"""

import os
import re
from urllib.parse import urljoin, urlsplit

import pytest

from app import product
from app.catalog import CATALOG

EXAM = os.environ.get("RANGE_EXAM", "0") == "1"

PRODUCT_PAGES = [
    "/login", "/dashboard", "/tickets", "/accounts", "/billing", "/files", "/reports",
    "/tools", "/integrations", "/team", "/admin", "/account", "/help-center", "/api-docs",
]

#: Endpoints a real SaaS would never link: they must stay undiscoverable except
#: by guessing, wordlists, robots.txt leaks or reading other material.
HIDDEN = {
    "/.git/config", "/.env", "/backup.sql", "/server-status", "/actuator/env", "/metrics",
    "/auth/admin", "/auth/admin/login", "/auth/superuser/login", "/auth/session/fixate",
    "/auth/oauth/callback", "/sso/callback", "/integrations/callback",
    "/account/reset/confirm", "/password/reset/done", "/errors/render", "/redirect/log",
    "/api/token/verify3",
}

#: Words a real product page would never use about itself.
LEAKY = re.compile(
    r"vulnerab|inject|\bxss\b|\bsqli\b|\bssrf\b|\bssti\b|\bxxe\b|\bidor\b|payload|exploit"
    r"|\bflag\b|\bcwe\b|owasp|traversal|\bcsrf\b|\bcors\b|\bcrlf\b|mass.assign",
    re.IGNORECASE,
)

HREF = re.compile(r'(?:href|action|src)=["\']([^"\'#]+)', re.IGNORECASE)


def _discoverable_text(client) -> str:
    """Everything a visitor can reach without the Academy: pages, bundle, docs, sitemap."""

    texts = [client.get(path).get_data(as_text=True) for path in PRODUCT_PAGES]
    for path in ("/js/app.js", "/api-docs", "/sitemap.xml", "/robots.txt"):
        texts.append(client.get(path).get_data(as_text=True))
    return "\n".join(texts)


@pytest.mark.parametrize("path", PRODUCT_PAGES + ["/js/app.js", "/robots.txt", "/sitemap.xml"])
def test_product_pages_load(client, path):
    assert client.get(path).status_code == 200


def test_every_page_has_the_navigation_and_search(client):
    body = client.get("/billing").get_data(as_text=True)
    for href, _label in product.NAV:
        assert f'href="{href}"' in body
    assert 'action="/search"' in body


def test_forms_submit_to_the_feature_not_the_page(client):
    body = client.get("/tools").get_data(as_text=True)
    assert 'action="/tools/ping"' in body
    assert 'name="host"' in body


def test_hidden_internals_are_never_linked(client):
    text = _discoverable_text(client)
    linked = {
        urlsplit(urljoin("http://x/", ref)).path
        for ref in HREF.findall(text)
    }
    for route in HIDDEN:
        assert route not in linked, f"{route} is linked from the product"
        assert f'"{route}' not in text and f"'{route}" not in text, f"{route} appears in the product"


def test_robots_leaks_a_few_private_paths_but_not_a_map(client):
    robots = client.get("/robots.txt").get_data(as_text=True)
    disallowed = [line for line in robots.splitlines() if line.startswith("Disallow:")]
    assert 3 <= len(disallowed) <= 8
    assert "Sitemap:" in robots


def test_sitemap_lists_public_pages_only(client):
    sitemap = client.get("/sitemap.xml").get_data(as_text=True)
    locations = re.findall(r"<loc>([^<]+)</loc>", sitemap)
    assert len(locations) == len(product.PUBLIC_PAGES)
    for route in HIDDEN:
        assert route not in sitemap


def test_only_the_users_own_object_ids_are_exposed(client):
    text = _discoverable_text(client)
    for vuln in (v for v in CATALOG if v.family == "idor"):
        foreign = str(vuln.extra["rid"])
        assert not re.search(rf"(?<!\d){foreign}(?!\d)", text), f"foreign id {foreign} is exposed"


def test_own_record_answers_without_a_flag(client):
    response = client.get(product.own("/api/tickets/<int:rid>"))
    assert response.status_code == 200
    assert "FLAG{" not in response.get_data(as_text=True)


def test_unknown_object_id_is_a_clean_404(client):
    # String-id routes used to crash with a 500 on any other id.
    for path in ("/api/files/999", "/api/payments/abc", "/api/v1/invoices/1"):
        assert client.get(path).status_code == 404


def test_product_copy_names_no_vulnerability(client):
    # Guided mode keeps a lab hint on /login and a flag counter on /dashboard, and
    # its footer says "training range" on purpose; the product content itself
    # (inside <main>) must read like a real SaaS in both modes.
    pages = PRODUCT_PAGES if EXAM else [p for p in PRODUCT_PAGES if p not in ("/login", "/dashboard")]
    for path in pages:
        body = client.get(path).get_data(as_text=True)
        main = re.search(r"<main[^>]*>(.*?)</main>", body, re.DOTALL)
        text = re.sub(r"<[^>]+>", " ", main.group(1) if main else body)
        match = LEAKY.search(text)
        assert match is None, f"{path} says '{match.group(0)}'"


@pytest.mark.skipif(not EXAM, reason="exam-mode presentation")
def test_exam_mode_pages_carry_no_lab_hints(client):
    for path in ("/login", "/dashboard", "/tickets"):
        body = client.get(path).get_data(as_text=True)
        assert "intentionally vulnerable" not in body
        assert "Flags captured" not in body
        # an actual Academy link, not the "/lab" inside every </label> tag
        assert not re.search(r"""["']/lab(?:/|["'])""", body)


@pytest.mark.skipif(EXAM, reason="the Academy only exists in guided mode")
def test_every_academy_lesson_loads(client):
    # Upload, parameter-pollution and XXE lessons used to crash with a 500.
    broken = [v.id for v in CATALOG if client.get(f"/lab/{v.id}").status_code != 200]
    assert broken == []


@pytest.mark.skipif(EXAM, reason="the landing page only exists in guided mode")
def test_landing_page_enters_the_site(client):
    body = client.get("/").get_data(as_text=True)
    assert 'href="/dashboard"' in body
