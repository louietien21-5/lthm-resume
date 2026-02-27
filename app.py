from flask import Flask, render_template

from content import SITE_DATA

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html", site=SITE_DATA)


if __name__ == "__main__":
    from waitress import serve

    host = "127.0.0.1"
    port = 5000
    print(f"Open: http://{host}:{port}")
    serve(app, host=host, port=port)
