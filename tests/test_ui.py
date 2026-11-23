import os

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("RANGE_EXAM", "0") == "1",
    reason="UI pages of the guided mode are not served in exam mode",
)


def test_landing_page(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"VulnWeb-Lab" in response.data


def test_academy_index(client):
    response = client.get("/lab/")
    assert response.status_code == 200
    assert b"VulnWeb-Lab Academy" in response.data


def test_academy_lesson(client):
    response = client.get("/lab/sqli-01")
    assert response.status_code == 200
    assert b"Concept" in response.data


def test_catalog_api(client):
    response = client.get("/api/catalog")
    assert response.status_code == 200
    payload = response.get_json()
    assert payload["count"] >= 200


def test_verify_api(client):
    from app import flags

    response = client.post("/api/verify", json={"flag": flags.flag_for("sqli-01")})
    assert response.status_code == 200
    assert response.get_json()["vuln_id"] == "sqli-01"


def test_verify_rejects_bad_flag(client):
    response = client.post("/api/verify", json={"flag": "FLAG{nope}"})
    assert response.status_code == 404


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["vulns"] >= 200
