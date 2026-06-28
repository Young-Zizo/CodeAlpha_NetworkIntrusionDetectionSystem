"""
log_pipeline.py
----------------
Tails Suricata's eve.json log, parses 'alert' events, deduplicates near-identical
repeated hits, assigns a severity tier, and persists rows into a SQLite database
that the dashboard reads from.

Usage:
    python3 log_pipeline.py --eve /var/log/suricata/eve.json --db ../alerts.db

Works for both:
  - live tailing of an actively-growing eve.json (Suricata running on an interface)
  - a static eve.json produced by an offline pcap replay (suricata -r file.pcap)
    -> in that case it just reads the whole file once and exits.
"""

import argparse
import json
import os
import sqlite3
import time
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    src_ip TEXT,
    src_port INTEGER,
    dest_ip TEXT,
    dest_port INTEGER,
    proto TEXT,
    signature TEXT,
    signature_id INTEGER,
    category TEXT,
    severity INTEGER,
    severity_tier TEXT,
    raw_json TEXT,
    dedup_key TEXT,
    hit_count INTEGER DEFAULT 1,
    first_seen TEXT,
    last_seen TEXT
);
CREATE INDEX IF NOT EXISTS idx_dedup ON alerts(dedup_key);
CREATE INDEX IF NOT EXISTS idx_timestamp ON alerts(timestamp);
"""

# Suricata's own "severity" field is 1 (high) - 3 (low) by ET ruleset convention.
# We map it to a human label and also bump anything matching our custom SIDs
# that we consider critical regardless of the field Suricata assigned.
SEVERITY_LABELS = {1: "HIGH", 2: "MEDIUM", 3: "LOW"}
FORCE_HIGH_SIDS = {9000010, 9000011, 9000021, 9000022, 9000023, 9000030}


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.executescript(SCHEMA)
    conn.commit()
    return conn


def severity_tier(sig_id: int, sev_field: int) -> str:
    if sig_id in FORCE_HIGH_SIDS:
        return "HIGH"
    return SEVERITY_LABELS.get(sev_field, "LOW")


def make_dedup_key(event: dict) -> str:
    alert = event.get("alert", {})
    return f"{event.get('src_ip')}|{event.get('dest_ip')}|{alert.get('signature_id')}"


def upsert_alert(conn: sqlite3.Connection, event: dict) -> None:
    alert = event.get("alert", {})
    sig_id = alert.get("signature_id", 0)
    sev_field = alert.get("severity", 3)
    dedup_key = make_dedup_key(event)
    ts = event.get("timestamp", datetime.now(timezone.utc).isoformat())

    cur = conn.cursor()
    cur.execute(
        "SELECT id, hit_count FROM alerts WHERE dedup_key=? AND timestamp > datetime('now','-5 minutes')",
        (dedup_key,),
    )
    row = cur.fetchone()

    if row:
        alert_db_id, hit_count = row
        cur.execute(
            "UPDATE alerts SET hit_count=?, last_seen=? WHERE id=?",
            (hit_count + 1, ts, alert_db_id),
        )
    else:
        cur.execute(
            """INSERT INTO alerts
               (timestamp, src_ip, src_port, dest_ip, dest_port, proto,
                signature, signature_id, category, severity, severity_tier,
                raw_json, dedup_key, hit_count, first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?)""",
            (
                ts,
                event.get("src_ip"),
                event.get("src_port"),
                event.get("dest_ip"),
                event.get("dest_port"),
                event.get("proto"),
                alert.get("signature"),
                sig_id,
                alert.get("category"),
                sev_field,
                severity_tier(sig_id, sev_field),
                json.dumps(event),
                dedup_key,
                ts,
                ts,
            ),
        )
    conn.commit()


def process_line(conn: sqlite3.Connection, line: str) -> None:
    line = line.strip()
    if not line:
        return
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return
    if event.get("event_type") != "alert":
        return
    upsert_alert(conn, event)


def read_once(conn: sqlite3.Connection, eve_path: str) -> int:
    """Read an existing static eve.json fully (offline pcap-replay use case)."""
    count = 0
    with open(eve_path, "r") as f:
        for line in f:
            process_line(conn, line)
            count += 1
    return count


def tail_file(conn: sqlite3.Connection, eve_path: str) -> None:
    """Follow a live-growing eve.json, like `tail -f`."""
    with open(eve_path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            process_line(conn, line)


def main():
    parser = argparse.ArgumentParser(description="Parse Suricata eve.json into SQLite")
    parser.add_argument("--eve", required=True, help="Path to eve.json")
    parser.add_argument("--db", default="alerts.db", help="Path to SQLite DB")
    parser.add_argument(
        "--mode",
        choices=["auto", "once", "tail"],
        default="auto",
        help="'once' = read file then exit (good for pcap-replay logs). "
        "'tail' = follow a live file. 'auto' tries 'once' then switches to tail.",
    )
    args = parser.parse_args()

    conn = init_db(args.db)
    print(f"[+] Using database: {args.db}")
    print(f"[+] Reading: {args.eve}")

    n = read_once(conn, args.eve)
    print(f"[+] Processed {n} existing log lines.")

    if args.mode == "once":
        print("[+] Done (mode=once).")
        return

    print("[+] Tailing for new alerts... (Ctrl+C to stop)")
    try:
        tail_file(conn, args.eve)
    except KeyboardInterrupt:
        print("\n[+] Stopped.")


if __name__ == "__main__":
    main()
