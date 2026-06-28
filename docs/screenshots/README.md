# Project Screenshots

This folder documents the working system end-to-end — from configuration validation through to
live detections on the dashboard.

### 01 — Suricata configuration loaded successfully
![Config loaded](01_suricata_yaml_loaded_successfully.png)
`suricata -T` test mode confirming the YAML config (custom rules, interfaces, HOME_NET) parses
and loads without errors.

### 02 — Suricata service running
![Service active](02_suricata_service_active_running.png)
`systemctl status suricata` showing the engine active and running as a system service, with
threads created on both the physical interface and loopback.

### 03 — Port Scan + C2 Beaconing detections
![Port scan and C2 alerts](03_port_scan_and_c2_alerts_detected.png)
Output of an Nmap SYN scan replayed against the lab host, showing both the
**Possible TCP Port Scan Detected** and **Possible C2 Beaconing Pattern** custom rules firing in
`eve.json`.

### 04 — SSH Brute Force detection
![SSH brute force alert](04_ssh_bruteforce_alert_detected.png)
Repeated SYN packets sent to port 22 (simulating brute-force connection attempts), correctly
flagged by the **CUSTOM Possible SSH Brute Force** rule.

### 05 — SQL Injection detection
![SQL injection alert](05_sql_injection_alert_detected.png)
A crafted HTTP request containing a UNION-based SQL injection payload, caught by the
**CUSTOM Possible SQL Injection Attempt** rule.

### 06 — Live dashboard overview
![Dashboard overview](06_dashboard_overview.png)
The Flask dashboard showing the live alert feed, severity breakdown, and top source IPs pulled
from the SQLite alert database.

### 07 — Final dashboard with all four custom detections
![All detections](07_dashboard_final_all_detections.png)
All four custom rules confirmed firing together: Port Scan, SSH Brute Force, SQL Injection, and
C2 Beaconing — alongside default Suricata ruleset alerts for context.
