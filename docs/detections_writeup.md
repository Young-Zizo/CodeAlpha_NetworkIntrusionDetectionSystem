# Detections Write-up

This document explains each custom rule in `rules/custom.rules`, why it matters, and what it
looks like when triggered. Use this as the basis for your LinkedIn video script and GitHub repo
write-up — add screenshots from your own dashboard in the placeholders below.

## Results from this build

All four detections below were tested end-to-end in a lab VM (Ubuntu 24.04, Suricata 8.0.5) and
confirmed firing correctly in the live dashboard:

| Rule | SID | Severity | Status |
|---|---|---|---|
| Possible TCP Port Scan Detected | 9000001 | MEDIUM | ✅ Confirmed |
| Possible SSH Brute Force | 9000010 | HIGH | ✅ Confirmed |
| Possible SQL Injection Attempt | 9000022 | HIGH | ✅ Confirmed |
| Possible C2 Beaconing Pattern | 9000030 | HIGH | ✅ Confirmed |

See `docs/screenshots/` for the dashboard captures referenced in the write-up below.

---

### SID 9000001 — Possible TCP Port Scan Detected
**What it does:** Flags a source IP sending 20+ TCP SYN packets to the protected network within
10 seconds — the signature of a scanning tool sweeping ports to find open services.
**Why it matters:** Port scanning is almost always the reconnaissance phase before an attack.
**Demo:** `nmap -sS <target>` from an attacker VM.
![Port scan alert](screenshots/03_port_scan_and_c2_alerts_detected.png)

### SID 9000002 — ICMP Ping Sweep Detected
**What it does:** Flags 10+ ICMP echo requests from one source within 10 seconds — host
discovery across a subnet.
**Demo:** `nmap -sn <subnet>/24` or a simple ping sweep script.

### SID 9000003 / 9000004 — NULL / Xmas Scan Flags Detected
**What it does:** Detects unusual TCP flag combinations (no flags set, or FIN+PSH+URG together)
used by stealth scanning techniques to evade simple firewalls and fingerprint OS behavior.
**Demo:** `nmap -sN <target>` (NULL scan) / `nmap -sX <target>` (Xmas scan).

### SID 9000010 — Possible SSH Brute Force
**What it does:** Flags 8+ SYNs to port 22 from one source within 30 seconds — repeated
connection attempts consistent with password-guessing tools like Hydra.
**Demo:** `sudo hping3 --syn -p 22 -c 15 -i u100000 127.0.0.1` (sends 15 SYN packets to port 22
in quick succession — confirmed working in this build).

### SID 9000011 — Possible FTP Brute Force
**What it does:** Flags repeated `USER` commands sent to an FTP server from one source — repeated
login attempts.

### SID 9000020 — Plaintext HTTP Basic Auth Credentials Seen
**What it does:** Flags any `Authorization: Basic` header in HTTP traffic — credentials sent in
base64 (not encryption) over an unencrypted channel.
**Why it matters:** This is a hygiene/policy finding, not necessarily an "attack" — it shows the
NIDS can also catch insecure configurations, not just malicious traffic.

### SID 9000021 — Possible DNS Tunneling (Long Subdomain)
**What it does:** Flags DNS queries with an unusually long alphanumeric subdomain label (40+
characters) — a common pattern for DNS tunneling tools used to exfiltrate data or maintain covert
C2 channels through DNS.

### SID 9000022 — Possible SQL Injection Attempt
**What it does:** Flags HTTP requests whose URI contains both "union" and "select" — a classic
UNION-based SQL injection probe pattern.
**Demo:** Run a simple HTTP server (`sudo python3 -m http.server 80`) and send:
`curl "http://127.0.0.1/index.html?id=1%20UNION%20SELECT%20username,password%20FROM%20users"`
— confirmed working in this build.

### SID 9000023 — Possible Directory Traversal Attempt
**What it does:** Flags `../../` sequences in HTTP request URIs — an attempt to escape the web
root and read arbitrary files.

### SID 9000030 — Possible C2 Beaconing Pattern
**What it does:** Flags a host inside the network opening 30+ outbound connections to a single
external destination within 60 seconds — consistent with malware "beaconing" to a command-and-
control server, or potentially data exfiltration.
**Why it matters:** Unlike the recon rules above (which look at inbound traffic), this one
specifically watches outbound behavior — important for catching an already-compromised host.

---

## Honest limitations (include this section in your write-up — reviewers respect it)

- All detections are **signature/threshold-based** — they catch known patterns and won't catch a
  truly novel attack technique.
- Thresholds (e.g. "20 SYNs in 10 seconds") are tuned for a small lab network; in a real
  enterprise network they'd need tuning to reduce false positives at scale.
- This is **detection only** — Suricata can also run inline as an IPS (active blocking), which
  would be a natural "future work" extension.
- Testing was done via **offline pcap replay** and/or self-generated lab traffic, not a live
  production network — say so explicitly rather than implying otherwise.
