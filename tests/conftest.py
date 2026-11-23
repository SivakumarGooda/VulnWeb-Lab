import os

import pytest

from app import create_app

EXAM = os.environ.get("RANGE_EXAM", "0") == "1"


@pytest.fixture(scope="session")
def app():
    return create_app(exam=EXAM)


@pytest.fixture()
def client(app):
    return app.test_client()
