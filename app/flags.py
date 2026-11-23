"""Deterministic per-vulnerability flags and the on-disk flag vault.

Flags are derived from the range secret so every process that shares the secret
(and the catalog) agrees on them. The secret is random by default and lives in
``instance/secret.key``; it is not part of the repository.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Iterable

import config


def flag_for(vuln_id: str) -> str:
    digest = hmac.new(
        config.SECRET.encode("utf-8"), vuln_id.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:12]
    safe = vuln_id.replace("-", "_").replace(".", "_")
    return f"FLAG{{orbit_{safe}_{digest}}}"


def ensure_vault(vulns: Iterable) -> None:
    """Write one flag file per vulnerability for traversal/RCE/SSRF exercises.

    Exam mode deliberately keeps every flag in memory so an exploit cannot read
    another challenge's proof from disk.
    """
    if config.EXAM:
        return
    config.VAULT_DIR.mkdir(parents=True, exist_ok=True)
    for vuln in vulns:
        path = config.VAULT_DIR / f"{vuln.id}.txt"
        if not path.exists():
            path.write_text(flag_for(vuln.id) + "\n", encoding="utf-8")

    # A few generic secrets referenced by information-disclosure exercises.
    extras = {
        "admin.env": "DATABASE_URL=postgres://orbitdesk:Orbit!2026@db.local/orbit\n"
        "API_KEY=sk-orbit-range-admin-key\n",
        "backup.sql": "-- OrbitDesk backup\nCREATE TABLE users (...);\n",
    }
    for name, body in extras.items():
        path = config.VAULT_DIR / name
        if not path.exists():
            path.write_text(body, encoding="utf-8")
