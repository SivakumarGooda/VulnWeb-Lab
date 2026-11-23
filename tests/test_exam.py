"""Exam-mode guarantees: no answers over HTTP and no cross-challenge flags."""
import os

import pytest

from app import config, flags
from app.catalog import BY_ID
from app.handlers import cmdi_payload, traversal_payload
EXAM = os.environ.get("RANGE_EXAM", "0") == "1"
pytestmark = pytest.mark.skipif(not EXAM, reason="run with RANGE_EXAM=1")


def test_root_redirects_to_login(client):
    response = client.get("/", follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_lab_is_hidden(client):
    assert client.get("/lab/").status_code == 404
    assert client.get("/lab/sqli-01").status_code == 404


def test_catalog_and_progress_are_hidden(client):
    assert client.get("/api/catalog").status_code == 404
    assert client.get("/api/solves").status_code == 404


def test_health_does_not_advertise_catalog(client):
    payload = client.get("/health").get_json()
    assert payload == {"status": "ok"}


def test_no_flag_artifacts_on_disk():
    assert not (config.INSTANCE_DIR / "secret.key").exists()
    assert not (config.INSTANCE_DIR / "range.db").exists()
    assert not (config.VAULT_DIR / "sqli-01.txt").exists()


def test_verify_still_works(client):
    response = client.post("/api/verify", json={"flag": flags.flag_for("sqli-01")})
    assert response.status_code == 200
    assert response.get_json()["vuln_id"] == "sqli-01"


def test_sqli_cannot_dump_other_flags(client):
    current = flags.flag_for("sqli-05")
    other = flags.flag_for("sqli-06")
    payload = "%' UNION SELECT 1,(SELECT group_concat(flag) FROM flags)--"
    response = client.get(
        "/api/v1/tickets/search", query_string={"q": payload}
    )
    body = response.get_data(as_text=True)
    assert current in body
    assert other not in body


def test_command_injection_only_reveals_its_own_flag(client):
    vuln = BY_ID["cmdi-01"]
    response = client.get(vuln.route, query_string={vuln.param: cmdi_payload(vuln)})
    body = response.get_data(as_text=True)
    assert flags.flag_for("cmdi-01") in body
    assert flags.flag_for("cmdi-02") not in body


def test_traversal_only_reveals_its_own_flag(client):
    vuln = BY_ID["traversal-01"]
    response = client.get(vuln.route, query_string={vuln.param: traversal_payload(vuln)})
    body = response.get_data(as_text=True)
    assert flags.flag_for("traversal-01") in body
    assert flags.flag_for("traversal-02") not in body


def test_xxe_does_not_read_source_in_exam(client):
    source = (config.BASE_DIR / "app" / "handlers.py").as_uri()
    payload = f'<!DOCTYPE r [<!ENTITY x SYSTEM "{source}">]><r>&x;</r>'
    response = client.post(
        "/api/xml/import", data=payload, headers={"Content-Type": "application/xml"}
    )
    body = response.get_data(as_text=True)
    assert flags.flag_for("xxe-01") in body
    assert "example_sequence" not in body
    assert "def h_sqli" not in body
