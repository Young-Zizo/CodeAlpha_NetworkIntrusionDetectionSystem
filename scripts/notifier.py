"""
notifier.py
-----------
Polls alerts.db for new HIGH severity alerts and pushes them to a Discord/Slack
webhook (both accept the same simple JSON POST format) or via email (SMTP).

Usage (webhook):
    python3 notifier.py --db ../alerts.db --webhook "https://discord.com/api/webhooks/..."

Usage (email):
    python3 notifier.py --db ../alerts.db --smtp-host smtp.gmail.com --smtp-port 587 \
        --smtp-user you@gmail.com --smtp-pass "app-password" --to-email you@gmail.com
"""

import argparse
import smtplib
import sqlite3
import time
from email.mime.text import MIMEText

import requests

POLL_SECONDS = 15


def get_new_high_alerts(conn: sqlite3.Connection, last_id: int):
    cur = conn.cursor()
    cur.execute(
        """SELECT id, timestamp, src_ip, dest_ip, signature, severity_tier
           FROM alerts
           WHERE id > ? AND severity_tier = 'HIGH'
           ORDER BY id ASC""",
        (last_id,),
    )
    return cur.fetchall()


def send_webhook(webhook_url: str, alert_row) -> None:
    _id, ts, src_ip, dest_ip, signature, tier = alert_row
    payload = {
        "content": (
            f"🚨 **{tier} severity alert**\n"
            f"**Signature:** {signature}\n"
            f"**Source:** {src_ip} → **Dest:** {dest_ip}\n"
            f"**Time:** {ts}"
        )
    }
    try:
        requests.post(webhook_url, json=payload, timeout=5)
    except requests.RequestException as e:
        print(f"[!] Webhook send failed: {e}")


def send_email(smtp_host, smtp_port, smtp_user, smtp_pass, to_email, alert_row) -> None:
    _id, ts, src_ip, dest_ip, signature, tier = alert_row
    body = f"Severity: {tier}\nSignature: {signature}\nSource: {src_ip}\nDest: {dest_ip}\nTime: {ts}"
    msg = MIMEText(body)
    msg["Subject"] = f"[NIDS] {tier} alert: {signature}"
    msg["From"] = smtp_user
    msg["To"] = to_email
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(smtp_user, [to_email], msg.as_string())
    except Exception as e:
        print(f"[!] Email send failed: {e}")


def main():
    parser = argparse.ArgumentParser(description="Notify on new HIGH severity NIDS alerts")
    parser.add_argument("--db", default="../alerts.db")
    parser.add_argument("--webhook", help="Discord/Slack webhook URL")
    parser.add_argument("--smtp-host")
    parser.add_argument("--smtp-port", type=int, default=587)
    parser.add_argument("--smtp-user")
    parser.add_argument("--smtp-pass")
    parser.add_argument("--to-email")
    args = parser.parse_args()

    if not args.webhook and not args.smtp_host:
        print("[!] Provide either --webhook or SMTP options.")
        return

    conn = sqlite3.connect(args.db)
    last_id = 0
    print("[+] Notifier running. Polling for HIGH severity alerts...")

    while True:
        rows = get_new_high_alerts(conn, last_id)
        for row in rows:
            print(f"[+] New HIGH alert: {row}")
            if args.webhook:
                send_webhook(args.webhook, row)
            if args.smtp_host:
                send_email(
                    args.smtp_host,
                    args.smtp_port,
                    args.smtp_user,
                    args.smtp_pass,
                    args.to_email,
                    row,
                )
            last_id = max(last_id, row[0])
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
