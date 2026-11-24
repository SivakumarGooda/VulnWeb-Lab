"""Real sign-in: sessions, the sign-in wall, and mail-based flows.

Honest use of the product must never produce a flag: signing in with the
right password, resetting your own password or using your own sign-in link
are normal features. Flags only come from abusing them.
"""
import re

from app import auth, mail

TESTER = {"email": "alice@orbitdesk.local", "password": "alice123"}


def _no_flag(response):
    text = response.get_data(as_text=True) + " ".join(response.headers.values())
    assert "FLAG{" not in text


def _latest_mail(mail_client, to: str, subject: str) -> dict:
    messages = [m for m in mail_client.get("/api/messages").get_json()
                if m["to"] == to and m["subject"] == subject]
    assert messages, f"no '{subject}' mail for {to}"
    return messages[-1]


def _link(message: dict) -> str:
    url = re.search(r"https?://\S+", message["body"]).group(0)
    return re.sub(r"^https?://[^/]+", "", url)


# --- the sign-in wall --------------------------------------------------------

def test_signed_out_visitors_are_sent_to_sign_in(anon):
    response = anon.get("/billing")
    assert response.status_code == 302
    assert response.headers["Location"].startswith("/login?next=/billing")


def test_signed_out_api_calls_get_401(anon):
    response = anon.get("/api/v1/tickets/search", query_string={"q": "x"})
    assert response.status_code == 401


def test_public_pages_stay_open(anon):
    for path in ("/login", "/help-center", "/api-docs", "/robots.txt", "/auth/magic-link",
                 "/account/forgot-password", "/auth/ldap", "/.env"):
        assert anon.get(path).status_code == 200, path


def test_signed_out_header_has_no_app_navigation(anon):
    body = anon.get("/login").get_data(as_text=True)
    assert 'href="/billing"' not in body
    assert "Sign in" in body


# --- signing in and out ------------------------------------------------------

def test_correct_password_signs_in_without_a_flag(anon):
    response = anon.post("/auth/login", data={**TESTER, "next": "/tickets"})
    assert response.status_code == 302
    assert response.headers["Location"] == "/tickets"
    _no_flag(response)
    page = anon.get("/dashboard")
    assert page.status_code == 200
    assert "Good morning, Alice" in page.get_data(as_text=True)
    _no_flag(page)


def test_wrong_password_is_refused(anon):
    response = anon.post("/auth/login", data={"email": TESTER["email"], "password": "nope"})
    assert "Incorrect email or password" in response.get_data(as_text=True)
    _no_flag(response)
    assert anon.get("/dashboard").status_code == 302


def test_sign_in_never_redirects_off_site(anon):
    response = anon.post("/auth/login", data={**TESTER, "next": "https://elsewhere.example/"})
    assert response.headers["Location"] == "/dashboard"


def test_sign_out_ends_the_session(client):
    assert client.get("/dashboard").status_code == 200
    client.get("/logout", query_string={"redirect": "/login"})
    assert client.get("/dashboard").status_code == 302


def test_keep_me_signed_in_survives_a_new_browser(app, anon):
    response = anon.post("/auth/login", data={**TESTER, "remember": "1"})
    cookie = re.search(r"remember=([^;]+)", " ".join(response.headers.getlist("Set-Cookie"))).group(1)
    fresh = app.test_client()
    fresh.set_cookie("remember", cookie)
    assert fresh.get("/dashboard").status_code == 200


def test_api_login_returns_a_working_token(anon):
    response = anon.post("/api/login", json={"username": "alice", "password": "alice123"})
    assert response.status_code == 200
    _no_flag(response)
    token = response.get_json()["token"]
    api = anon.get("/api/v1/tickets/search", query_string={"q": "x"},
                   headers={"Authorization": f"Bearer {token}"})
    assert api.status_code == 200


def test_sign_in_page_offers_only_normal_options(anon):
    body = anon.get("/login").get_data(as_text=True)
    for hidden in ("/auth/otp", "/auth/2fa", "/auth/login-legacy", "/auth/demo/login",
                   "/auth/support/login", "/auth/staff", "/auth/admin"):
        assert f'"{hidden}"' not in body, hidden


# --- two-step verification ---------------------------------------------------

def test_two_step_account_needs_the_emailed_code(anon, mail_client):
    response = anon.post("/auth/login", data={"email": "bob@orbitdesk.local", "password": "bob123"})
    assert response.headers["Location"] == "/auth/2fa"
    assert anon.get("/dashboard").status_code == 302          # not signed in yet
    # Bob's code goes to Bob's mailbox, which the tester can't read.
    assert all(m["to"] != "bob@orbitdesk.local" for m in mail_client.get("/api/messages").get_json())
    wrong = anon.post("/auth/2fa", data={"code": "123", "verified": "false"})
    assert "That code didn" in wrong.get_data(as_text=True)
    right = anon.post("/auth/2fa", data={"code": auth.CODES["bob@orbitdesk.local"], "verified": "false"})
    assert right.status_code == 302
    _no_flag(right)
    assert anon.get("/dashboard").status_code == 200


# --- mail-based flows on your own account ------------------------------------

def test_own_password_reset_arrives_by_mail(anon, mail_client):
    response = anon.post("/account/forgot-password", data={"email": TESTER["email"]})
    assert "emailed you a link" in response.get_data(as_text=True)
    assert "token=" not in response.get_data(as_text=True)    # never shown on the page
    link = _link(_latest_mail(mail_client, TESTER["email"], "Reset your OrbitDesk password"))
    page = anon.get(link)
    assert "Choose a new password" in page.get_data(as_text=True)
    _no_flag(page)


def test_own_magic_link_signs_in(anon, mail_client):
    anon.post("/auth/magic-link", data={"email": TESTER["email"]})
    link = _link(_latest_mail(mail_client, TESTER["email"], "Your OrbitDesk sign-in link"))
    response = anon.get(link)
    assert response.status_code == 302
    _no_flag(response)
    assert anon.get("/dashboard").status_code == 200


def test_own_one_time_code_signs_in(anon, mail_client):
    anon.post("/auth/otp", data={"email": TESTER["email"]})
    message = _latest_mail(mail_client, TESTER["email"], "Your OrbitDesk sign-in code")
    code = re.search(r"\b(\d{6})\b", message["body"]).group(1)
    response = anon.post("/auth/otp", data={"email": TESTER["email"], "code": code})
    assert response.status_code == 302
    _no_flag(response)


def test_contact_form_confirmation_has_no_internal_details(anon, mail_client):
    anon.post("/contact", data={"email": TESTER["email"], "subject": "Hello there", "message": "Hi"})
    message = _latest_mail(mail_client, TESTER["email"], "We received your message")
    assert "FLAG{" not in message["body"]
    assert "internal" not in message["body"].lower()


# --- other people's mail stays private ----------------------------------------

def test_victim_mail_is_never_shown(anon, mail_client):
    anon.post("/account/forgot-password", data={"email": "admin@orbitdesk.local"})
    anon.post("/auth/magic-link", data={"email": "admin@orbitdesk.local"})
    for message in mail_client.get("/api/messages").get_json():
        assert message["to"] in (TESTER["email"],) or message["to"].endswith("@inbox.test")


def test_victim_clicks_only_reach_hosts_the_tester_controls(anon, mail_client):
    before = len(mail_client.get("/api/requests").get_json())
    anon.post("/account/forgot-password", data={"email": "admin@orbitdesk.local"},
              headers={"X-Forwarded-Host": "evil.example"})
    assert len(mail_client.get("/api/requests").get_json()) == before


def test_mailbox_logs_requests_to_it(mail_client):
    mail_client.get("/hello-from-ssrf?x=1")
    paths = [r["path"] for r in mail_client.get("/api/requests").get_json()]
    assert "/hello-from-ssrf?x=1" in paths


def test_mailbox_pages_render(mail_client):
    assert mail_client.get("/").status_code == 200
    assert mail_client.get("/requests").status_code == 200
    first = mail.inbox()
    if first:
        assert mail_client.get(f"/message/{first[0]['id']}").status_code == 200
