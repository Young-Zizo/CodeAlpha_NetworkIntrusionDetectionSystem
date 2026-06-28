# CodeAlpha_NetworkIntrusionDetectionSystem

A Network-based Intrusion Detection System (NIDS) built on **Suricata**, with a custom Python
alert-processing pipeline, SQLite storage, a live Flask dashboard, and a webhook/email notifier
for high-severity events.

> Built for the CodeAlpha Cyber Security Internship — Task 4.

## Live Dashboard

![Dashboard with all detections](docs/screenshots/07_dashboard_final_all_detections.png)

All 4 custom rules confirmed firing in this build: **Port Scan**, **SSH Brute Force**,
**SQL Injection**, and **C2 Beaconing** — see `docs/screenshots/README.md` for the full
walkthrough with all 7 screenshots (config validation → service running → each detection →
final dashboard).

---

---

## Architecture

```
                ┌────────────────┐
   Traffic ───▶ │   Suricata     │  (IDS mode — detection only, no blocking)
 (pcap replay)  │  + custom.rules│
                └───────┬────────┘
                        │ writes
                        ▼
                  eve.json (JSON alert log)
                        │
                        ▼
              ┌──────────────────┐
              │ log_pipeline.py  │  tails eve.json, parses, dedupes,
              │                  │  classifies severity, stores rows
              └─────────┬────────┘
                         ▼
                  alerts.db (SQLite)
                         │
            ┌────────────┴─────────────┐
            ▼                           ▼
     ┌─────────────┐           ┌─────────────────┐
     │ Flask        │           │ notifier.py      │
     │ dashboard    │           │ (Discord/Slack/  │
     │ (live charts)│           │  email webhook)  │
     └─────────────┘           └─────────────────┘
```

---

## 1. Set up the VM

1. Install **Ubuntu Server 22.04 LTS** in VirtualBox or VMware (2 CPU / 2GB RAM is enough).
2. Update the system:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

## 2. Install Suricata

```bash
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update
sudo apt install suricata -y
suricata --build-info   # confirm install
```

Find your network interface name:
```bash
ip a
```

## 3. Configure Suricata

Edit `/etc/suricata/suricata.yaml`:

- Set `HOME_NET` to your VM's subnet, e.g. `"[192.168.1.0/24]"`.
- Under `outputs:` make sure `eve-log` is enabled with `filetype: regular` and
  `filename: eve.json` (default path: `/var/log/suricata/eve.json`).
- Point the default rules + your custom rules:
  ```yaml
  default-rule-path: /etc/suricata/rules
  rule-files:
    - suricata.rules
    - custom.rules
  ```

Copy this project's `rules/custom.rules` into `/etc/suricata/rules/custom.rules`.

## 4. Run Suricata against a pcap file (offline / replay mode)

This is the safest and most reproducible way to demo detections — no live attack traffic needed,
and anyone cloning your repo can rerun the exact same test.

```bash
sudo suricata -r sample_pcaps/sample_traffic.pcap -c /etc/suricata/suricata.yaml -l /var/log/suricata/
```

Check alerts fired:
```bash
cat /var/log/suricata/eve.json | grep '"event_type":"alert"' | python3 -m json.tool
```

> **Where to get pcaps:** Use publicly available, legal sample captures meant for IDS testing —
> e.g. the sample files bundled with Wireshark (`Help → About Wireshark → Folders → sample
> captures` after install), or the small test pcaps in the Suricata source repo's `qa/` folder.
> Avoid downloading pcaps from untrusted third-party sites.

## 5. Run the alert pipeline

```bash
cd scripts
pip3 install -r requirements.txt
python3 log_pipeline.py --eve /var/log/suricata/eve.json --db ../alerts.db
```

This tails `eve.json` continuously, parses each alert, deduplicates repeated hits, assigns a
severity tier, and writes rows into `alerts.db`.

## 6. Run the dashboard

```bash
cd dashboard
pip3 install -r requirements.txt
python3 app.py
```

Visit `http://<vm-ip>:5000` to see:
- Live alert feed
- Alerts over time (chart)
- Top source IPs
- Severity breakdown

## 7. (Optional) Enable notifications

Edit `scripts/notifier.py`, add your Discord/Slack webhook URL or SMTP credentials, then run it
alongside `log_pipeline.py` — it polls `alerts.db` and pushes new high-severity alerts out.

```bash
python3 notifier.py --db ../alerts.db --webhook "<your webhook url>"
```

---

## Repo structure

```
CodeAlpha_NetworkIntrusionDetectionSystem/
├── README.md
├── rules/
│   └── custom.rules          # hand-written detection rules
├── scripts/
│   ├── log_pipeline.py       # eve.json -> SQLite
│   ├── notifier.py           # SQLite -> webhook/email alerts
│   └── requirements.txt
├── dashboard/
│   ├── app.py                # Flask app
│   ├── templates/
│   │   └── dashboard.html
│   └── requirements.txt
├── sample_pcaps/
│   └── README.md             # where to get legal test pcaps
└── docs/
    └── detections_writeup.md # explanation of each custom rule + screenshots placeholder
```

## What to put in your LinkedIn video / GitHub write-up

1. Explain *why* IDS matters (visibility vs. prevention — IDS detects, IPS blocks).
2. Walk through 2–3 of your custom rules and show the matching alert in the dashboard.
3. Show the architecture diagram above.
4. Mention real limitations (no inline blocking, single-host lab, signature-based — won't catch
   zero-days) — reviewers respect honesty about scope far more than overclaiming.

## Notes for your write-up: limitations to be upfront about

- This is **signature-based detection** — it catches known patterns, not novel attacks.
- Running in **offline/replay mode** against pcaps for the demo (rather than live traffic) is a
  legitimate and common testing approach, but say so explicitly — don't imply it was caught live
  in production.
- It is **detection only**, not prevention (could mention Suricata's inline/IPS mode as future
  work).
