import os
import hmac
import shutil
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import urlparse

from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from content import SITE_DATA
from stats_service import (
    build_dashboard_data,
    build_raw_events_data,
    get_import_options,
    import_plaintext_source,
)


def _resolve_stats_dir(project_root: Path) -> Path:
    configured = os.getenv("STATS_DIR", "").strip()
    if configured:
        return Path(configured).expanduser()

    # App Service deployments commonly mount the app package as read-only.
    # Use the persistent data volume by default when running on Azure.
    if os.getenv("WEBSITE_SITE_NAME", "").strip():
        return Path("/home/site/data/stats")

    return project_root / "stats"


def _seed_stats_dir(stats_dir: Path, bundled_stats_dir: Path) -> None:
    if not bundled_stats_dir.exists() or not bundled_stats_dir.is_dir():
        return

    try:
        same_dir = stats_dir.resolve() == bundled_stats_dir.resolve()
    except OSError:
        same_dir = stats_dir == bundled_stats_dir
    if same_dir:
        return

    try:
        stats_dir.mkdir(parents=True, exist_ok=True)
        if any(stats_dir.iterdir()):
            return
    except OSError:
        return

    for item in bundled_stats_dir.iterdir():
        if not item.is_file():
            continue
        target = stats_dir / item.name
        try:
            shutil.copy2(item, target)
        except OSError:
            # Best effort: continue if a single file cannot be copied.
            continue


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", os.getenv("SECRET_KEY", os.urandom(32)))
    # Trust Azure/App Service proxy headers for scheme/host/IP handling.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    project_root = Path(__file__).resolve().parent
    bundled_stats_dir = project_root / "stats"
    stats_dir = _resolve_stats_dir(project_root)
    _seed_stats_dir(stats_dir=stats_dir, bundled_stats_dir=bundled_stats_dir)
    import_options = get_import_options()

    def _stats_password() -> str:
        return os.getenv("STATS_PASSWORD", "").strip()

    def _safe_next_path(candidate: str) -> str:
        if not candidate:
            return url_for("stats_page")

        parsed = urlparse(candidate)
        if parsed.scheme or parsed.netloc:
            return url_for("stats_page")
        if not candidate.startswith("/stats"):
            return url_for("stats_page")
        return candidate

    def _stats_auth_redirect():
        if not _stats_password():
            abort(503, description="STATS_PASSWORD is not configured.")
        if session.get("stats_authenticated"):
            return None

        next_target = request.full_path if request.query_string else request.path
        return redirect(url_for("stats_login", next=next_target))

    def _import_context(
        feedback: Optional[Dict[str, str]] = None,
        selected_source: Optional[str] = None,
    ) -> Dict[str, object]:
        if feedback is None:
            feedback = session.pop("stats_import_feedback", None)
        if selected_source is None:
            selected_source = session.pop("stats_import_selected_source", "")
        if not selected_source and import_options:
            selected_source = import_options[0]["key"]
        return {
            "import_options": import_options,
            "import_feedback": feedback,
            "import_selected_source": selected_source,
        }

    @app.get("/")
    def home():
        return render_template("index.html", site=SITE_DATA)

    @app.get("/dans-penis")
    def dans_penis():
        art = """⠀⠀⠀⠀⠀⠀⠀⣠⣤⣤⣤⣤⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢰⡿⠋⠁⠀⠀⠈⠉⠙⠻⣷⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣿⠇⠀⢀⣴⣶⡾⠿⠿⠿⢿⣿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣀⣀⣸⡿⠀⠀⢸⣿⣇⠀⠀⠀⠀⠀⠀⠙⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⣾⡟⠛⣿⡇⠀⠀⢸⣿⣿⣷⣤⣤⣤⣤⣶⣶⣿⠇⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀
⢀⣿⠀⢀⣿⡇⠀⠀⠀⠻⢿⣿⣿⣿⣿⣿⠿⣿⡏⠀⠀⠀⠀⢴⣶⣶⣿⣿⣿⣆
⢸⣿⠀⢸⣿⡇⠀⠀⠀⠀⠀⠈⠉⠁⠀⠀⠀⣿⡇⣀⣠⣴⣾⣮⣝⠿⠿⠿⣻⡟
⢸⣿⠀⠘⣿⡇⠀⠀⠀⠀⠀⠀⠀⣠⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠁⠉⠀
⠸⣿⠀⠀⣿⡇⠀⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠉⠀⠀⠀⠀
⠀⠻⣷⣶⣿⣇⠀⠀⠀⢠⣼⣿⣿⣿⣿⣿⣿⣿⣛⣛⣻⠉⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⣿⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢸⣿⣀⣀⣀⣼⡿⢿⣿⣿⣿⣿⣿⡿⣿⣿⣿"""
        return f"<pre>{art}</pre>"

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok"), 200

    @app.get("/stats/login")
    def stats_login():
        if not _stats_password():
            return render_template(
                "stats_login.html",
                error="Set STATS_PASSWORD before opening this page.",
                next_path=url_for("stats_page"),
                password_configured=False,
            )

        if session.get("stats_authenticated"):
            return redirect(url_for("stats_page"))

        return render_template(
            "stats_login.html",
            error=None,
            next_path=_safe_next_path(request.args.get("next", "")),
            password_configured=True,
        )

    @app.post("/stats/login")
    def stats_login_submit():
        configured_password = _stats_password()
        if not configured_password:
            abort(503, description="STATS_PASSWORD is not configured.")

        candidate = request.form.get("password", "")
        next_path = _safe_next_path(request.form.get("next_path", ""))
        if hmac.compare_digest(candidate, configured_password):
            session["stats_authenticated"] = True
            return redirect(next_path)

        return (
            render_template(
                "stats_login.html",
                error="Wrong password.",
                next_path=next_path,
                password_configured=True,
            ),
            401,
        )

    @app.post("/stats/logout")
    def stats_logout():
        session.pop("stats_authenticated", None)
        return redirect(url_for("stats_login"))

    @app.get("/stats")
    def stats_page():
        auth_redirect = _stats_auth_redirect()
        if auth_redirect:
            return auth_redirect

        window = request.args.get("window", "90d")
        dashboard = build_dashboard_data(stats_dir=stats_dir, window=window)
        return render_template("stats.html", dashboard=dashboard)

    @app.get("/stats/dashboard")
    def stats_dashboard():
        auth_redirect = _stats_auth_redirect()
        if auth_redirect:
            return auth_redirect

        window = request.args.get("window", "90d")
        dashboard = build_dashboard_data(stats_dir=stats_dir, window=window)
        return render_template("partials/stats_dashboard.html", dashboard=dashboard)

    @app.get("/stats/raw")
    def stats_raw():
        auth_redirect = _stats_auth_redirect()
        if auth_redirect:
            return auth_redirect

        raw = build_raw_events_data(
            stats_dir=stats_dir,
            window=request.args.get("window", "90d"),
            source=request.args.get("source", "all"),
            day=request.args.get("day", ""),
            limit=request.args.get("limit", "120"),
        )
        return render_template("partials/stats_raw_table.html", raw=raw)

    @app.get("/stats/import")
    def stats_import_page():
        auth_redirect = _stats_auth_redirect()
        if auth_redirect:
            return auth_redirect

        return render_template("stats_import.html", **_import_context())

    @app.post("/stats/import")
    def stats_import_plaintext():
        auth_redirect = _stats_auth_redirect()
        if auth_redirect:
            return auth_redirect

        source = request.form.get("source", "").strip()
        payload = request.form.get("payload", "")
        selected_source = source if source else None

        try:
            result = import_plaintext_source(stats_dir=stats_dir, source=source, payload=payload)
            feedback = {
                "level": "ok",
                "text": (
                    "Imported {0} lines into {1}. "
                    "{2} unique events written ({3} non-event lines ignored)."
                ).format(
                    int(result["incoming_events"]),
                    str(result["target_file"]),
                    int(result["written_events"]),
                    int(result["ignored_lines"]),
                ),
            }
        except ValueError as exc:
            feedback = {"level": "error", "text": str(exc)}
        except OSError:
            feedback = {
                "level": "error",
                "text": "Could not write import file in {0}. Configure STATS_DIR to a writable path.".format(
                    stats_dir
                ),
            }

        session["stats_import_feedback"] = feedback
        if selected_source:
            session["stats_import_selected_source"] = selected_source
        return redirect(url_for("stats_import_page"))

    return app


app = create_app()


if __name__ == "__main__":
    from waitress import serve

    host = os.getenv("HOST", "localhost")
    port = int(os.getenv("PORT", "8000"))
    threads = int(os.getenv("WAITRESS_THREADS", "8"))
    print(f"Open: http://{host}:{port}")
    serve(app, host=host, port=port, threads=threads)
