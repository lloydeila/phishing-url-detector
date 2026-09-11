from flask import Flask, render_template, request
from flask_limiter import Limiter
from detector import analyze_url, save_scan
import csv
import os


app = Flask(__name__)


limiter = Limiter(
    app=app,
    key_func=lambda: request.remote_addr
)


HISTORY_FILE = "scan_history.csv"


def get_scan_history():
    """Read scan history from CSV file."""

    if not os.path.exists(HISTORY_FILE):
        return []

    with open(
        HISTORY_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        reader = csv.DictReader(file)

        return list(reader)


def get_statistics(scans):
    """Calculate dashboard statistics."""

    total = len(scans)

    high_risk = sum(
        1
        for scan in scans
        if scan["Verdict"] == "HIGH RISK"
    )

    suspicious = sum(
        1
        for scan in scans
        if scan["Verdict"] == "SUSPICIOUS"
    )

    low_risk = sum(
        1
        for scan in scans
        if scan["Verdict"] == "LOW RISK"
    )

    return {
        "total": total,
        "high_risk": high_risk,
        "suspicious": suspicious,
        "low_risk": low_risk
    }


@app.route("/", methods=["GET", "POST"])
def home():

    result = None

    if request.method == "POST":

        url = request.form.get(
            "url",
            ""
        ).strip()

        if url:

            score, verdict, indicators = analyze_url(
                url
            )

            timestamp = save_scan(
                url,
                score,
                verdict,
                indicators
            )

            result = {
                "url": url,
                "score": score,
                "verdict": verdict,
                "indicators": indicators,
                "timestamp": timestamp
            }

    scans = get_scan_history()

    statistics = get_statistics(
        scans
    )

    return render_template(
        "index.html",
        result=result,
        scans=scans,
        statistics=statistics
    )


# API ENDPOINT

@app.route("/api/analyze", methods=["POST"])
@limiter.limit("10 per minute")
def api_analyze():

    data = request.get_json()

    if not data or "url" not in data:
        return {
            "error": "Please provide a URL."
        }, 400

    url = data["url"]

    if not isinstance(url, str):
        return {
            "error": "URL must be a string."
        }, 400

    url = url.strip()

    if not url:
        return {
            "error": "URL cannot be empty."
        }, 400

    score, verdict, indicators = analyze_url(
        url
    )

    timestamp = save_scan(
        url,
        score,
        verdict,
        indicators
    )

    return {
        "url": url,
        "score": score,
        "verdict": verdict,
        "indicators": indicators,
        "timestamp": timestamp
    }, 200


if __name__ == "__main__":

    app.run(
        debug=True
    )