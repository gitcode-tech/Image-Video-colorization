from flask import Flask, render_template, request, redirect

from analyzer import analyze_log
from database import initialize_database, get_alerts


app = Flask(__name__)

initialize_database()


@app.route("/")
def index():
    alerts = get_alerts()

    return render_template(
        "index.html",
        alerts=alerts
    )


@app.route("/analyze", methods=["POST"])
def analyze():
    filename = request.form.get("filename")

    if not filename:
        return redirect("/")

    try:
        analyze_log(filename)
    except FileNotFoundError:
        return "Log file was not found.", 404

    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)
