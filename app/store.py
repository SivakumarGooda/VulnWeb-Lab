"""Small SQLite/in-memory store that backs the range.

Guided mode uses a file database under ``instance/`` and a shared flag vault.
Exam mode uses an in-memory store with one SQLite database per SQL-injection
challenge, so an injection can only read its own flag and a command injection
cannot read another challenge's proof from disk.
"""
from __future__ import annotations

import base64
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Iterable

import config
from . import flags

STATE: dict[str, Any] = {}
SOLVES: set[str] = set()
EXAM_DBS: dict[str, sqlite3.Connection] = {}
_EXAM_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, role TEXT
);
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY, title TEXT, owner TEXT
);
CREATE TABLE IF NOT EXISTS flags (
    vuln_id TEXT PRIMARY KEY, flag TEXT
);
CREATE TABLE IF NOT EXISTS solves (
    vuln_id TEXT PRIMARY KEY, solved_at TEXT
);
"""

USERS = [
    (1, "admin@orbitdesk.local", "Adm1n-" + base64.urlsafe_b64encode(config.SECRET.encode())[:12].decode(), "admin"),
    (2, "alice@orbitdesk.local", "alice123", "user"),
    (3, "bob@orbitdesk.local", "bob123", "user"),
]

ITEMS = [
    (1, "Printer on floor 3 is offline", "alice"),
    (2, "Quarterly access review", "bob"),
    (3, "Invoice INV-2026-041", "alice"),
    (4, "Onboarding checklist", "admin"),
]


def _connect() -> sqlite3.Connection:
    con = sqlite3.connect(config.DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    return con


def _seed(con: sqlite3.Connection, vulns: Iterable | None = None, vuln_id: str | None = None) -> None:
    con.executescript(SCHEMA)
    con.execute("DELETE FROM users")
    con.execute("DELETE FROM items")
    con.execute("DELETE FROM flags")
    con.executemany("INSERT INTO users(id, email, password, role) VALUES (?,?,?,?)", USERS)
    con.executemany("INSERT INTO items(id, title, owner) VALUES (?,?,?)", ITEMS)
    if vuln_id is not None:
        con.execute(
            "INSERT INTO flags(vuln_id, flag) VALUES (?,?)",
            (vuln_id, flags.flag_for(vuln_id)),
        )
    elif vulns is not None:
        con.executemany(
            "INSERT INTO flags(vuln_id, flag) VALUES (?,?)",
            [(v.id, flags.flag_for(v.id)) for v in vulns],
        )
    con.commit()


def init(vulns: Iterable) -> None:
    vulns = list(vulns)
    dirs = [config.INSTANCE_DIR, config.FILES_DIR, config.UPLOAD_DIR]
    if not config.EXAM:
        dirs.append(config.VAULT_DIR)
    for path in dirs:
        path.mkdir(parents=True, exist_ok=True)

    (config.FILES_DIR / "welcome.txt").write_text(
        "Welcome to OrbitDesk files.\nThis file is safe to download.\n", encoding="utf-8"
    )
    (config.FILES_DIR / "quarterly-report.txt").write_text(
        "Quarterly support report - Q3 2026\n", encoding="utf-8"
    )
    (config.UPLOAD_DIR / "existing.txt").write_text(
        "Pre-existing upload placeholder.\n", encoding="utf-8"
    )

    STATE.clear()
    SOLVES.clear()

    if config.EXAM:
        EXAM_DBS.clear()
        _seed_idor(vulns)
        return

    con = _connect()
    try:
        _seed(con, vulns=vulns)
        for row in con.execute("SELECT vuln_id FROM solves"):
            SOLVES.add(row["vuln_id"])
    finally:
        con.close()

    _seed_idor(vulns)


def _seed_idor(vulns: Iterable) -> None:
    for vuln in vulns:
        if vuln.family == "idor":
            STATE[f"resource:{vuln.id}"] = {
                "id": vuln.extra.get("rid"),
                "tenant": "northwind",
                "owner": "victim@northwind.example",
                "kind": vuln.extra.get("kind", "record"),
                "secret_note": "board acquisition memo",
                "flag": flags.flag_for(vuln.id),
            }


def raw_query(sql: str) -> list[sqlite3.Row]:
    con = _connect()
    try:
        return list(con.execute(sql))
    finally:
        con.close()


def query_for(vuln, sql: str) -> list[sqlite3.Row]:
    """Run a vulnerable query against the challenge's own database in exam mode."""
    if not config.EXAM:
        return raw_query(sql)
    # The server is threaded: share each in-memory database across threads,
    # one query at a time.
    with _EXAM_LOCK:
        con = EXAM_DBS.get(vuln.id)
        if con is None:
            con = sqlite3.connect(":memory:", check_same_thread=False)
            con.row_factory = sqlite3.Row
            _seed(con, vuln_id=vuln.id)
            EXAM_DBS[vuln.id] = con
        return list(con.execute(sql))


def verify_flag(flag: str) -> dict[str, Any] | None:
    from .catalog import CATALOG

    flag = (flag or "").strip()
    for vuln in CATALOG:
        if flags.flag_for(vuln.id) == flag:
            return {
                "valid": True,
                "vuln_id": vuln.id,
                "title": vuln.title,
                "category": vuln.category,
                "family": vuln.family,
                "difficulty": vuln.difficulty,
            }
    return None


def mark_solved(vuln_id: str) -> None:
    SOLVES.add(vuln_id)
    if config.EXAM:
        return
    con = _connect()
    try:
        con.execute(
            "INSERT OR REPLACE INTO solves(vuln_id, solved_at) VALUES (?,?)",
            (vuln_id, datetime.now(timezone.utc).isoformat(timespec="seconds")),
        )
        con.commit()
    finally:
        con.close()


def solved() -> set[str]:
    return set(SOLVES)
