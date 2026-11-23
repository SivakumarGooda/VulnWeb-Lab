"""Runtime configuration for VulnWeb-Lab.

Everything is stored under an instance directory so the range is disposable.

Modes:
* guided (default) - flags are stable and written to ``instance/vault`` so the
  Academy can show file-based exploits. Convenient for learning.
* exam (``RANGE_EXAM=1`` or ``--exam``) - no flags or secret on disk, a fresh
  random secret per process, no Academy/catalog endpoints, and per-vulnerability
  flag isolation so one exploit cannot harvest the whole scoreboard.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
EXAM = os.environ.get("RANGE_EXAM", "0") == "1"

INSTANCE_DIR = BASE_DIR / "instance"
VAULT_DIR = INSTANCE_DIR / "vault"
FILES_DIR = INSTANCE_DIR / "files"
UPLOAD_DIR = INSTANCE_DIR / "uploads"
DB_PATH = INSTANCE_DIR / "range.db"


def _load_secret() -> str:
    """Guided mode: a stable secret shared by the site and academy processes."""
    env = os.environ.get("RANGE_SECRET", "").strip()
    if env:
        return env
    instance = BASE_DIR / "instance"
    instance.mkdir(parents=True, exist_ok=True)
    path = instance / "secret.key"
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = secrets.token_hex(32)
    path.write_text(value, encoding="utf-8")
    return value


# Exam mode never reads or writes a secret; each process gets a fresh one.
SECRET = secrets.token_hex(32) if EXAM else _load_secret()

HOST = os.environ.get("RANGE_HOST", "127.0.0.1")
PORT = int(os.environ.get("RANGE_PORT", "8080"))

# When RANGE_SAFE=1 the command-injection and local-file-read endpoints are
# disabled. Handy when running outside a container on a machine you care about.
SAFE_MODE = os.environ.get("RANGE_SAFE", "0") == "1"

AUDIT_HEADER = "X-Range-Audit"


def begin_exam() -> None:
    """Switch this process to exam mode before the app is built.

    Uses a separate ``instance-exam`` directory, writes no secret/database/vault,
    and rotates flags on every start.
    """
    global EXAM, SECRET, INSTANCE_DIR, VAULT_DIR, FILES_DIR, UPLOAD_DIR, DB_PATH
    EXAM = True
    SECRET = secrets.token_hex(32)
    os.environ.pop("RANGE_SECRET", None)

    INSTANCE_DIR = BASE_DIR / "instance-exam"
    VAULT_DIR = INSTANCE_DIR / "vault"
    FILES_DIR = INSTANCE_DIR / "files"
    UPLOAD_DIR = INSTANCE_DIR / "uploads"
    DB_PATH = INSTANCE_DIR / "range.db"


def exam_artifacts_present() -> list[str]:
    """Paths that would leak guided-mode answers if visible during an exam."""
    candidates = [
        BASE_DIR / "instance" / "vault",
        BASE_DIR / "instance" / "secret.key",
        BASE_DIR / "instance" / "range.db",
    ]
    return [str(path) for path in candidates if path.exists()]


def summary() -> dict[str, str]:
    return {
        "host": HOST,
        "port": str(PORT),
        "mode": "exam" if EXAM else "guided",
        "safe_mode": "on" if SAFE_MODE else "off",
        "instance_dir": str(INSTANCE_DIR),
    }
