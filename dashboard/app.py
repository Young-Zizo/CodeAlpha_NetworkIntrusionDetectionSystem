"""
app.py — Flask dashboard for the NIDS alert database.

Run:
    python3 app.py
Then visit http://<host>:5000
"""

import sqlite3
from collections import Counter
from pathlib import Path

from flask import Flask, jsonify, render_template

DB_PATH = Path(__file__).resolve().parent.parent / "alerts.db"

app = Flask(__name__)


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/alerts")
def api_alerts():
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY id DESC LIMIT 100"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/summary")
def api_summary():
    conn = get_conn()
    rows = conn.execute("SELECT severity_tier, src_ip, signature, timestamp FROM alerts").fetchall()
    conn.close()

    severity_counts = Counter(r["severity_tier"] for r in rows)
    top_src_ips = Counter(r["src_ip"] for r in rows).most_common(10)
    top_signatures = Counter(r["signature"] for r in rows).most_common(10)

    # group alerts per hour (based on the timestamp prefix) for a simple time series
    timeline = Counter()
    for r in rows:
        ts = r["timestamp"] or ""
        bucket = ts[:13] if len(ts) >= 13 else ts  # YYYY-MM-DDTHH
        timeline[bucket] += 1
    timeline_sorted = sorted(timeline.items())

    return jsonify(
        {
            "total_alerts": len(rows),
            "severity_counts": severity_counts,
            "top_src_ips": top_src_ips,
            "top_signatures": top_signatures,
            "timeline": timeline_sorted,
        }
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
