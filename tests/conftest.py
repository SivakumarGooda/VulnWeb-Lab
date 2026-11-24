import os

import pytest

from app import create_app
from app.handlers import capture, fill_step
from app.mail import create_mail_app

EXAM = os.environ.get("RANGE_EXAM", "0") == "1"

TESTER = {"email": "alice@orbitdesk.local", "password": "alice123"}


@pytest.fixture(scope="session")
def app():
    return create_app(exam=EXAM)


@pytest.fixture(scope="session")
def mail_app():
    return create_mail_app()


@pytest.fixture()
def anon(app):
    """A visitor who is not signed in."""
    return app.test_client()


@pytest.fixture()
def client(app):
    """Signed in as the tester's own account, alice."""
    test_client = app.test_client()
    response = test_client.post("/auth/login", data=TESTER)
    assert response.status_code == 302, response.get_data(as_text=True)[:300]
    return test_client


@pytest.fixture()
def mail_client(mail_app):
    return mail_app.test_client()


def run_steps(client, mail_client, steps):
    """Replay an example sequence, mailbox steps and captured values included."""

    values: dict[str, str] = {}
    response = None
    for raw in steps:
        step = fill_step(raw, values)
        target = mail_client if step.get("server") == "mail" else client
        headers = dict(step.get("headers") or {})
        # The test client owns its cookie jar; a raw Cookie header is ignored.
        for name, value in list(headers.items()):
            if name.lower() == "cookie":
                for part in value.split(";"):
                    key, _, cookie_value = part.strip().partition("=")
                    if key:
                        target.set_cookie(key, cookie_value)
                headers.pop(name)
        kwargs = {"method": step.get("method", "GET"), "headers": headers}
        if step.get("query"):
            kwargs["query_string"] = step["query"]
        if "files" in step:
            kwargs["data"] = step["files"]
            kwargs["content_type"] = "multipart/form-data"
        elif step.get("json") is not None:
            kwargs["json"] = step["json"]
        elif step.get("data") is not None:
            kwargs["data"] = step["data"]
        response = target.open(step["path"], **kwargs)
        capture(step, response.get_data(as_text=True), values)
    return response
