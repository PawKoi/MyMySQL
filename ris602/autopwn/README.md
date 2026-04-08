# AutoPwn — Automated Penetration Testing Framework

A modular, multi-phase automated pentest tool targeting corporate lab networks.
Chains discovery → enumeration → exploitation → post-exploitation → reporting in a single command.

---

## Quick Start

```bash
# Full scan (recommended: run as root for ARP scan + masscan)
sudo python3 main.py --target 172.16.25.0/26

# MSSQL focused only
sudo python3 main.py --target 172.16.25.0/26 --mssql-only

# No brute force (faster, quieter)
sudo python3 main.py --target 172.16.25.0/26 --no-brute

# Deep scan with custom output dir
sudo python3 main.py --target 172.16.25.5 --speed deep --out /root/pentest_results
```

---

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | required | CIDR, single IP, or range (e.g. `192.168.1.1-10`) |
| `--speed` | `fast` | `fast` / `balanced` / `deep` |
| `--out` | `/tmp/autopwn_<ts>` | Output directory |
| `--iface` | auto | Network interface for ARP scan |
| `--no-brute` | off | Skip all brute force modules |
| `--mssql-only` | off | Discovery + full MSSQL chain only |

---

## Speed Profiles

| Profile | nmap timing | Brute force | Threads | Use case |
|---------|-------------|-------------|---------|----------|
| `fast` | T4 | disabled | 10 | Quick recon, CTF, time-limited |
| `balanced` | T3 | enabled | 20 | Default pentest |
| `deep` | T2 | enabled | 30 | Thorough, stealth-aware |

---

## Output Structure

```
/tmp/autopwn_YYYYMMDD_HHMMSS/
├── autopwn_full.log          ← Full timestamped log of every command
├── discovery/
│   ├── live_hosts.txt        ← All discovered hosts
│   ├── nmap_pingsweep.gnmap
│   └── masscan_sweep.txt
├── portscan/
│   └── <host>/
│       ├── nmap_tcp.txt      ← Full nmap service scan
│       ├── nmap_udp.txt
│       └── nmap_vuln.txt     ← Vuln scripts
├── services/
│   ├── mssql/<host>/         ← nmap NSE, impacket output, exploit results
│   ├── smb/<host>/           ← enum4linux, CME, smbclient, rpcclient
│   ├── http/<host>/          ← headers, nikto, whatweb, gobuster, sqlmap
│   ├── ldap/<host>/          ← ldapsearch user/group dump
│   ├── dns/<host>/           ← zone transfers, dnsrecon
│   ├── snmp/<host>/          ← community strings, snmpwalk OIDs
│   ├── ssh/<host>/           ← banner, auth methods, hydra
│   ├── ftp/<host>/           ← anonymous login, hydra
│   ├── rdp/<host>/           ← NLA check, BlueKeep
│   ├── nfs/<host>/           ← showmount, auto-mount attempt
│   └── vpn/<host>/           ← OpenVPN, IKE aggressive mode
├── evasion/                  ← Firewall type, WAF vendor, NAT detection
├── post/
│   └── pivot_map.txt         ← Lateral movement candidates
├── loot/
│   ├── credentials.txt       ← All found username:password pairs
│   ├── hashes.txt            ← NTLM/NTLMv2/Kerberos hashes
│   └── leaked_ips.txt        ← Internal IPs found in responses
└── reports/
    ├── final_report.txt      ← Human-readable summary
    ├── report.html           ← Dark-theme HTML with severity tables
    └── findings.json         ← Machine-readable full findings dump
```

---

## Phase Order

1. **Host Discovery** — nmap ping sweep, ARP scan, masscan, TCP connect, ICMP
2. **Port Scanning** — masscan all-ports + nmap service/version + vuln scripts
3. **OS Fingerprinting** — nmap OS, TTL, SMB banner, SSH banner, HTTP Server header
4. **Firewall Detection** — ACK/FIN/NULL/XMAS/Window scans → classify stateful/stateless
5. **WAF Detection** — wafw00f + 14 manual HTTP probe signatures
6. **NAT Detection** — traceroute hop analysis, TTL pattern matching
7. **Evasion Engine** — builds per-host evasion config (timing, fragmentation, source port, decoys)
8. **Banner Grab** — raw TCP grab on all open ports
9. **MSSQL** — nmap NSE → CME → impacket SA probe → xp_cmdshell → linked servers → MSF
10. **SMB** — nmap → enum4linux-ng → CME → smbclient → rpcclient → EternalBlue → MS08-067 → relay
11. **HTTP** — headers → robots.txt → nikto → whatweb → gobuster/ffuf → testssl → sqlmap → CORS/SSRF
12. **LDAP** — anonymous rootDSE → user/group dump → ldapsearch → brute
13. **DNS** — zone transfer (AXFR) → FQDN resolution → dnsrecon → open resolver check
14. **SNMP** — community string brute (onesixtyone) → snmpwalk → snmp-check
15. **SSH** — banner → auth methods → user enum (CVE-2018-15473) → hydra
16. **FTP** — banner → vsFTPd 2.3.4 backdoor → anon login → hydra
17. **RDP** — NLA check → BlueKeep (CVE-2019-0708) → MS12-020 → hydra
18. **NFS** — showmount → world-readable exports → auto-mount attempt
19. **VPN** — OpenVPN UDP 1194 → IKE aggressive mode → PSK hash capture
20. **Generic Vuln Scan** — nmap `--script vuln,exploit` on all open ports
21. **Loot Collection** — walk all output files, extract creds/hashes/IPs with dedup
22. **Hash Cracking** — john (jumbo rules) or hashcat (NTLM/NTLMv2/krb5)
23. **Credential Spraying** — test each found credential against every other host (SMB/SSH/MSSQL/WinRM)
24. **Pivot Mapping** — traceroute hop analysis, SSH/RDP/WinRM accessibility matrix
25. **Reporting** — TXT summary + dark HTML report + JSON findings dump

---

## Required Tools

Tools are **auto-detected** at runtime. The framework skips modules gracefully when a tool is missing.

**Core (essential):**
```
nmap hydra
```

**Recommended (significantly improves coverage):**
```
masscan arp-scan crackmapexec enum4linux-ng smbclient rpcclient
ldapsearch gobuster nikto whatweb dnsrecon dig snmpwalk onesixtyone
```

**Optional (adds deeper capability):**
```
msfconsole impacket-mssqlclient sqlmap ffuf testssl wafw00f
ike-scan showmount john hashcat openssl
```

**Install on Kali / Parrot:**
```bash
sudo apt update && sudo apt install -y \
  nmap masscan arp-scan hydra crackmapexec enum4linux-ng \
  smbclient rpcclient ldap-utils gobuster nikto whatweb \
  dnsrecon snmp snmpwalk onesixtyone python3-impacket \
  sqlmap ffuf testssl.sh wafw00f ike-scan nfs-common \
  john hashcat openssl
```

---

## Wordlists

The tool uses **SecLists** and **rockyou** if present, and falls back to built-in lists automatically:

```bash
# Install SecLists
sudo apt install seclists
# or
git clone https://github.com/danielmiessler/SecLists /usr/share/seclists
```

---

## Environment Variables

```bash
export AUTOPWN_SPEED=balanced   # fast | balanced | deep
export AUTOPWN_OUT=/root/results
sudo python3 main.py --target 172.16.25.0/26
```

---

## Extending

Each phase is a standalone Python module with a single `run(ctx)` function.
The `Context` object (`ctx`) carries all shared state:

```python
ctx.live_hosts      # set of IP strings
ctx.open_ports      # {host: {tcp: [ports], udp: [ports]}}
ctx.service_map     # {host: {port: {service, version}}}
ctx.os_map          # {host: "Windows / Linux"}
ctx.findings        # list of {severity, host, title, detail}
ctx.loot            # {credentials, hashes, rce, leaked_ips, ...}
ctx.evasion_map     # {host: {firewall, waf, engine_cfg}}
```

Add a new module:
```python
# services/mysql/mysql_enum.py
from core.executor import safe_run
from core.logger import get_logger

def run(ctx):
    log = get_logger()
    for host in ctx.live_hosts:
        if 3306 not in ctx.open_ports.get(host,{}).get("tcp",[]): continue
        rc, out, _ = safe_run(f"nmap --script mysql-info -p3306 {host}", timeout=60)
        if out:
            ctx.add_finding("INFO", host, "MySQL service", out[:300])
```

Then add it to `main.py` phases list:
```python
(3, "MySQL Enum", mysql_enum.run),
```

---

## Notes

- Run as **root** for ARP scan, masscan, and OS fingerprinting (raw socket access required)
- MSSQL SA login uses **SQL auth** (not Windows auth) — correct for default SA accounts
- All phases are exception-isolated — one failure never stops the rest
- Ctrl+C at any point triggers a **partial report** of everything gathered so far
- The `--mssql-only` flag is tuned for corp.local lab: targets `ad.corp.local` MSSQL first
