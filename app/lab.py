"""The guided Academy interface.

The Academy renders the same catalog as lessons: concept, objective, steps,
hints, the exact vulnerable route, example requests, flag submission, and
remediation guidance.
"""
from __future__ import annotations

import json
from collections import defaultdict

from flask import Blueprint, jsonify, redirect, render_template, request, url_for

import config

from . import store
from .catalog import BY_ID, CATALOG, counts, manifest
from .handlers import example_sequence

bp = Blueprint("lab", __name__, url_prefix="/lab")

DIFFICULTY_ORDER = {"easy": 0, "medium": 1, "hard": 2}


@bp.get("/")
def index():
    grouped: dict[str, list] = defaultdict(list)
    for vuln in CATALOG:
        grouped[vuln.category].append(vuln)
    solved = store.solved()
    total = len(CATALOG)
    return render_template(
        "lab_index.html",
        grouped=dict(sorted(grouped.items())),
        counts=counts(),
        total=total,
        solved=len(solved),
        solved_ids=solved,
    )


@bp.get("/scoreboard")
def scoreboard():
    solved = store.solved()
    rows = [v for v in CATALOG if v.id in solved]
    return render_template(
        "lab_scoreboard.html",
        rows=rows,
        total=len(CATALOG),
        solved=len(solved),
    )


@bp.get("/<vid>")
def detail(vid: str):
    vuln = BY_ID.get(vid)
    if vuln is None:
        return redirect(url_for("lab.index"))
    sequence = example_sequence(vuln)
    solved = vid in store.solved()
    message = request.args.get("message", "")
    return render_template(
        "lab_detail.html",
        v=vuln,
        sequence=sequence,
        solved=solved,
        message=message,
        curl=describe_sequence(vuln, sequence),
    )


@bp.post("/verify")
def verify():
    raw_flag = request.form.get("flag", "")
    info = store.verify_flag(raw_flag)
    if info:
        store.mark_solved(info["vuln_id"])
    if request.is_json or request.accept_mimetypes.best == "application/json":
        return jsonify(info or {"valid": False})
    vid = request.form.get("vuln_id", "")
    message = (
        f"Solved: {info['title']}" if info else "That flag does not match any vulnerability."
    )
    if vid:
        return redirect(url_for("lab.detail", vid=vid, message=message))
    return redirect(url_for("lab.scoreboard", message=message))


@bp.get("/api/catalog")
def api_catalog():
    return jsonify({"count": len(CATALOG), "families": counts(), "vulnerabilities": manifest()})


@bp.get("/api/stats")
def api_stats():
    solved = store.solved()
    return jsonify({"total": len(CATALOG), "solved": len(solved), "solved_ids": sorted(solved)})


@bp.post("/reset")
def reset():
    import config  # noqa: F401  (kept for symmetry)
    import sqlite3

    from .store import _connect  # local import to keep the public API small

    con = _connect()
    try:
        con.execute("DELETE FROM solves")
        con.commit()
    finally:
        con.close()
    store.SOLVES.clear()
    return redirect(url_for("lab.scoreboard"))


def describe_sequence(vuln, sequence) -> list[str]:
    """Turn a request sequence into readable curl commands for the lesson."""
    lines: list[str] = []
    for step in sequence:
        method = step.get("method", "GET").upper()
        path = step.get("path", "")
        query = step.get("query") or {}
        if query:
            # dict, or a list of pairs when a parameter repeats (HTTP pollution)
            pairs = query.items() if isinstance(query, dict) else query
            encoded = "&".join(f"{key}={value}" for key, value in pairs)
            path = f"{path}?{encoded}"
        port = config.MAIL_PORT if step.get("server") == "mail" else config.PORT
        if step.get("server") == "mail":
            lines.append("# check your mailbox")
        parts = [f"curl -i -X {method} 'http://127.0.0.1:{port}{path}'"]
        for key, value in (step.get("headers") or {}).items():
            parts.append(f"-H '{key}: {value}'")
        data = step.get("data")
        if isinstance(data, dict) and data:
            body = "&".join(f"{k}={v}" for k, v in data.items())
            parts.append(f"--data '{body}'")
        elif data:
            # a raw body, e.g. an XML document
            parts.append(f"--data-binary '{data}'")
        if step.get("json") is not None:
            parts.append(f"-H 'Content-Type: application/json'")
            parts.append("--data '" + json.dumps(step["json"]) + "'")
        if step.get("files"):
            # (stream, filename) or (stream, filename, content_type)
            for field, spec in step["files"].items():
                filename = spec[1]
                content_type = f";type={spec[2]}" if len(spec) > 2 and spec[2] else ""
                parts.append(f"-F '{field}=@/path/to/local/{filename}{content_type}'")
        lines.append(" ".join(parts))
        for name in step.get("capture") or {}:
            lines.append(f"# copy the {name} from that response into {{{name}}} below")
    return lines
