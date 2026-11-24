"""Application factory.

There are two modes:

* **learning** (default): OrbitDesk plus the Academy at ``/lab``.
* **exam**: OrbitDesk only. The Academy, the catalog and the progress API are
  gone, and flags live in memory and change on every start.

The old mode names still work: ``both`` and ``lab`` mean learning, ``site``
means exam (it used to hide the Academy but still served the answer list).
"""
from __future__ import annotations

from flask import Flask, jsonify, redirect, render_template, request

import config
from . import flags, store
from .catalog import CATALOG, counts

#: Old mode names, kept so existing commands and scripts keep working.
LEGACY_MODES = {"both": "learn", "lab": "learn", "learn": "learn", "site": "exam", "exam": "exam"}


def resolve_mode(mode: str = "learn", exam: bool | None = None) -> str:
    """``learn`` or ``exam`` from a mode name, the exam flag and RANGE_EXAM."""

    if exam or config.EXAM:
        return "exam"
    return LEGACY_MODES.get(str(mode or "learn").lower(), "learn")


def create_app(mode: str = "learn", exam: bool | None = None) -> Flask:
    mode = resolve_mode(mode, exam)
    exam = mode == "exam"
    if exam:
        config.begin_exam()

    app = Flask(__name__, instance_relative_config=False)
    app.secret_key = config.SECRET
    # "session" is left free for the session-fixation exercise's own cookie.
    app.config["SESSION_COOKIE_NAME"] = "orbit_session"
    app.config["RANGE_MODE"] = mode
    app.config["RANGE_EXAM"] = exam

    store.init(CATALOG)
    flags.ensure_vault(CATALOG)

    from .site import bp as site_bp

    app.register_blueprint(site_bp)

    if not exam:
        from .lab import bp as lab_bp

        app.register_blueprint(lab_bp)

    from . import auth

    app.before_request(auth.gate)

    @app.context_processor
    def _inject_mode():
        from .product import NAV

        return {"exam": config.EXAM, "nav": NAV, "user": auth.current_user()}

    @app.get("/")
    def landing():
        if exam:
            return redirect("/login")
        return render_template(
            "landing.html",
            total=len(CATALOG),
            families=counts(),
            safe_mode=config.SAFE_MODE,
        )

    @app.post("/api/verify")
    def verify_flag():
        payload = request.get_json(silent=True) or request.form
        info = store.verify_flag(payload.get("flag", ""))
        if info:
            store.mark_solved(info["vuln_id"])
            return jsonify(info)
        return jsonify({"valid": False}), 404

    @app.get("/health")
    def health():
        if exam:
            return jsonify({"status": "ok"})
        return jsonify({"status": "ok", "mode": mode, "vulns": len(CATALOG)})

    if not exam:
        @app.get("/api/solves")
        def solves():
            return jsonify({"solved": sorted(store.solved()), "total": len(CATALOG)})

        @app.get("/api/catalog")
        def catalog_api():
            from .catalog import manifest

            return jsonify({"count": len(CATALOG), "vulnerabilities": manifest()})

    if exam:
        leftovers = config.exam_artifacts_present()
        if leftovers:
            app.logger.warning(
                "Exam mode is using %s, but guided-mode flag artifacts exist at: %s. "
                "Use a clean container or remove the guided instance directory for "
                "strict isolation.",
                config.INSTANCE_DIR,
                ", ".join(leftovers),
            )

    return app
