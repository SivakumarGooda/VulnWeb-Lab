from collections import Counter

from app.catalog import CATALOG, FAMILIES, counts
from app import flags


def test_catalog_has_more_than_200_entries():
    assert len(CATALOG) >= 200


def test_every_family_is_represented():
    present = {v.family for v in CATALOG}
    assert present == set(FAMILIES)


def test_ids_are_unique():
    ids = [v.id for v in CATALOG]
    assert len(ids) == len(set(ids))


def test_routes_are_unique_per_method():
    pairs = [(v.method.upper(), v.route) for v in CATALOG]
    duplicates = [pair for pair, n in Counter(pairs).items() if n > 1]
    assert not duplicates, duplicates


def test_flags_are_unique():
    values = [flags.flag_for(v.id) for v in CATALOG]
    assert len(values) == len(set(values))


def test_guided_content_present():
    for v in CATALOG:
        assert v.concept.strip()
        assert v.objective.strip()
        assert v.steps
        assert v.hints
        assert v.remediation.strip()
        assert v.cwe.startswith("CWE-")


def test_family_counts_add_up():
    assert sum(counts().values()) == len(CATALOG)
