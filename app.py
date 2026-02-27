import os

from flask import Flask, jsonify, render_template
from werkzeug.middleware.proxy_fix import ProxyFix

from content import SITE_DATA


def create_app() -> Flask:
    app = Flask(__name__)
    # Trust Azure/App Service proxy headers for scheme/host/IP handling.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    @app.get("/")
    def home():
        return render_template("index.html", site=SITE_DATA)

    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok"), 200

    return app


app = create_app()


if __name__ == "__main__":
    from waitress import serve

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    threads = int(os.getenv("WAITRESS_THREADS", "8"))
    print(f"Open: http://{host}:{port}")
    serve(app, host=host, port=port, threads=threads)
