"""Application factory for both interfaces."""
from __future__ import annotations

from flask import Flask, jsonify, redirect, render_template, request

import config
from . import flags, store
from .catalog import CATALOG, counts


def create_app(mode: str = "both", exam: bool | None = None) -> Flask:
    exam = bool(exam) or config.EXAM
    if exam:
        config.begin_exam()
        mode = "site"

    app = Flask(__name__, instance_relative_config=False)
    app.secret_key = config.SECRET
    app.config["RANGE_MODE"] = mode
    app.config["RANGE_EXAM"] = exam

    store.init(CATALOG)
    flags.ensure_vault(CATALOG)

    from .site import bp as site_bp

    app.register_blueprint(site_bp)

    if mode != "site" and not exam:
        from .lab import bp as lab_bp

        app.register_blueprint(lab_bp)

    @app.context_processor
    def _inject_mode():
        from .product import NAV

        return {"exam": config.EXAM, "nav": NAV}

    @app.get("/")
    def landing():
        if exam:
            return redirect("/login")
        if mode == "lab":
            return redirect("/lab")
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
