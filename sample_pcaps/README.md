# Sample PCAPs

This folder is where you'll place pcap files to replay through Suricata for testing.

**Do not commit large pcaps to GitHub.** Either:
- Add a `.gitignore` entry for `*.pcap`, or
- Keep only one small (<5MB) demo pcap committed, and document where the rest came from.

## Legal sources for test pcaps

- **Wireshark sample captures** — bundled with Wireshark / listed at
  `wiki.wireshark.org/SampleCaptures`. Good for general protocol traffic.
- **Suricata's own test suite** — small pcaps used in Suricata's QA process, included in the
  Suricata source repository.
- **Your own lab traffic** — capture traffic you generate yourself in your VM (e.g. run `nmap
  -sS localhost` against another VM you own, capture with `tcpdump -w mytest.pcap`). This is the
  most defensible approach for a portfolio project: it's traffic you generated, on infrastructure
  you own, and you can describe exactly how it was made.

Avoid downloading pcaps from unknown or unofficial third-party sites — provenance matters, both
for safety (some "attack pcaps" floating around online contain real malware artifacts) and for
credibility when you explain your testing methodology.

## Generating your own test pcap (recommended for the LinkedIn demo)

In your lab (two VMs on the same host-only network):

```bash
# On the target VM, start a capture
sudo tcpdump -i eth0 -w sample_traffic.pcap

# On an attacker VM, generate traffic that should trigger your custom rules
nmap -sS <target-ip>          # triggers CUSTOM Possible TCP Port Scan Detected
ping -c 15 <target-ip>        # triggers CUSTOM ICMP Ping Sweep Detected
nmap -sN <target-ip>          # triggers NULL scan rule
```

Stop the capture, then replay it offline:
```bash
sudo suricata -r sample_traffic.pcap -c /etc/suricata/suricata.yaml -l /var/log/suricata/
```
