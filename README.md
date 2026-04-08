# MyMySQL
# RIS602 - MyMy

> **Isolated VM environment.**
> **Pawan Koirala**

---
---

## What This Is

`MyMy` is a modular Python + Bash penetration testing framework built for controlled lab environments. You run one command and it automatically discovers hosts, scans ports, brute-forces services, exploits where possible, collects loot, pivots through SSH tunnels to discover deeper networks, and generates reports - all hands-off.

---
---

## Quick Start

```bash
# Full auto-scan (auto-detects your subnet)
sudo bash run.sh

# Target a specific subnet
sudo bash run.sh --target 10.0.0.0/24

# Target with speed setting
sudo bash run.sh --target 10.0.0.0/24 --speed balanced

# Skip brute force (faster, quieter)
sudo bash run.sh --target 10.0.0.0/24 --no-brute

# Exclude certain IPs (e.g. your gateway)
sudo bash run.sh --target 10.0.0.0/24 --exclude 10.0.0.1

# Deep pivot mode (follows via/routed subnets too)
sudo bash run.sh --target 10.0.0.0/24 --deep-pivot
```

---
---

## File & Folder Reference

```
ris602/
│
├── run.sh                      ← MAIN ENTRY POINT - run this
├── excluded_run.sh             ← Same as run.sh but pre-configured excludes
├── admin_scan.sh               ← Admin-focused variant
├── private_scan.sh             ← For internal/private network ranges
├── private_scan_deep.sh        ← Slower, more thorough internal scan
├── private_scan_router.sh      ← Targets the gateway/router specifically
├── command.sh                  ← Quick one-off command runner
├── rm_pycache.sh               ← Cleanup: removes all __pycache__ dirs for a fresh start
│
├── wordlists/
│   ├── usernames.txt           ← Used by SSH brute-force (Hydra)
│   ├── passwords.txt           ← Full password list
│   ├── passwords_fast.txt      ← Trimmed list for faster pivot brute
│   ├── mysql_passwords.txt     ← MySQL-specific password list
│   ├── dirs.txt                ← Web directory fuzzing list
│   └── hydra.restore           ← Auto-generated Hydra resume file (gitignore this)
│
├── msf_results/                ← Metasploit output dumps land here
│
└── autopwn/
    ├── main.py                 ← Python entry point - orchestrates all phases
    ├── config.py               ← All settings: speeds, ports, wordlist paths, tools
    ├── README.md               ← (original autopwn notes)
    │
    ├── core/
    │   ├── utils.py            ← Helpers: CIDR expansion, IP parsing, dir creation
    │   ├── logger.py           ← Coloured logger, phase tracking, banners
    │   ├── executor.py         ← safe_run() wrapper for shell commands w/ timeout
    │   └── reporter.py         ← Assembles TXT / HTML / JSON reports from ctx
    │
    ├── discovery/
    │   ├── host_discovery.py   ← Ping sweep / ARP scan to find live hosts
    │   ├── port_scanner.py     ← nmap/masscan port scan on found hosts
    │   └── os_fingerprint.py   ← OS detection via nmap -O / banner grab
    │
    ├── services/
    │   ├── http/
    │   │   ├── http_enum.py        ← Directory brute (gobuster/ffuf)
    │   │   ├── http_fuzz.py        ← Parameter fuzzing
    │   │   ├── http_vuln.py        ← Common CVE checks
    │   │   ├── http_ssl.py         ← SSL/TLS cert and cipher checks
    │   │   └── http_proxy_abuse.py ← Open proxy detection
    │   │
    │   ├── ssh/
    │   │   └── ssh_brute.py        ← SSH brute-force via Hydra
    │   │
    │   ├── mysql/
    │   │   ├── mysql_brute.py      ← MySQL credential brute-force
    │   │   ├── mysql_exploit.py    ← Post-auth MySQL exploitation
    │   │   └── mysql_msf.py        ← Launches Metasploit MySQL modules
    │   │
    │   ├── generic/
    │       ├── banner_grab.py      ← TCP banner grabbing on any port
    │       └── vuln_scan.py        ← Generic nmap --script vuln runner
    │
    ├── post/
    │   ├── loot_collector.py       ← Grabs creds/files from compromised hosts
    │   ├── credential_tester.py    ← Replays found creds against other services
    │   ├── pivot_scanner.py        ← SSH tunnel pivot scanner (see breakdown below)
    │   ├── pivot_mapper.py         ← Traceroute-based pivot path mapper
    │   ├── hash_cracker.py         ← Runs John/Hashcat on collected hashes
    │
    └── report/
        ├── mysql_report.py         ← MySQL-specific formatted report
        └── templates/              ← HTML/text report templates
```

---
---

## How The Main Script Works - Step by Step

This is what happens when you run `sudo bash run.sh`:

### Step 1 - `run.sh` kicks off

- Checks you're running as **root** (needed for ARP scan and raw sockets)
- Checks **python3** is installed
- If you didn't pass `--target`, it **auto-detects your network interface and subnet** using `ip route`
- Figures out your own IP so it can **exclude itself** from scans automatically
- Then hands off to: `python3 autopwn/main.py --target <subnet> --speed <speed> --exclude <your_ip>`

---
---

### Step 2 - `main.py` sets up the Context object

- Creates an **output directory** under `/tmp/autopwn_<timestamp>/`
- Builds a `Context` object - this is a shared data store passed into every module. It holds:
  - `live_hosts` - set of IPs that responded to discovery
  - `open_ports` - dict of `{host: {tcp:[ports], udp:[ports]}}`
  - `service_map` - dict of `{host: {port: {service, version}}}`
  - `findings` - list of vulnerabilities found (each with severity, host, title, detail)
  - `loot` - credentials, hashes, pivot paths, leaked IPs, etc.
- Sets the speed profile (`fast` / `balanced` / `deep`) from `config.py`

---
---

### Step 3 - Host Discovery

**File:** `discovery/host_discovery.py`

- Ping sweep or ARP scan across the target CIDR
- ARP is more reliable on local subnets (ICMP is often blocked by firewalls)
- Populates `ctx.live_hosts` with IPs that are actually up

---
---

### Step 4 - Port Scanning

**File:** `discovery/port_scanner.py`

- Runs **nmap** or **masscan** against every live host
- Timing is set by speed profile: `T4` (fast), `T3` (balanced), `T2` (deep)
- Populates `ctx.open_ports` and `ctx.service_map`

---
---

### Step 5 - Service Attacks (run in sequence on each host)

Based on what ports are open, these modules fire:

#### MySQL Brute - `services/mysql/mysql_brute.py`
- Port **3306** open -> Hydra brute with `mysql_passwords.txt`
- Tries `root` user by default
- Credentials stored in `ctx.loot["credentials"]` if found

#### MySQL Exploit - `services/mysql/mysql_exploit.py`
- Takes found MySQL creds and runs **full recon**:
  - Dumps all databases, tables, columns, and rows
  - Searches for columns named `pass`, `token`, `secret`, `email`, `ssn`, etc.
  - Runs `mysqldump` for a full `.sql` backup of each database
  - Checks `FILE` privilege (lets you read/write OS files through MySQL)

#### SSH Brute - `services/ssh/ssh_brute.py`
- Port **22** open -> Hydra with `usernames.txt` + `passwords_fast.txt`
- Found SSH creds are important - they unlock the pivot scanner in the next phase

---
---

### Step 6 - Loot Collection

**File:** `post/loot_collector.py`

- Connects to compromised hosts using found credentials
- Collects config files, bash history, `/etc/shadow`, etc.
- Any leaked IPs found in configs get added to `ctx.loot["leaked_ips"]` - these feed back into the scan queue for recursive scanning

---
---

### Step 7 - Pivot Scanner (the most interesting part)

**File:** `post/pivot_scanner.py`

> **Plain English:** "I have SSH access to Machine A. Machine A can see a different internal network I can't reach from my attack box. So I tunnel through Machine A to attack that new network — without ever installing anything on Machine A."

Here's exactly how it works:

1. Takes all SSH credentials found in previous phases
2. Connects to each SSH host
3. Runs `ip route` on the remote machine to see **what subnets it can reach**
4. For each new subnet (not scanned before):
   - Probes every IP in that subnet for **port 3306** (MySQL) and **port 22** (SSH)
   - This is done by opening SSH `direct-tcpip` channels - pure tunnel, no tools needed on the pivot host
   - Multiple subnets are scanned in **parallel threads**
5. If **MySQL found** through tunnel:
   - Brutes it through the tunnel using a local port forward
   - On success: full database dump through the same tunnel (version, all DBs, all tables, all data, sensitive column search, mysqldump)
6. If **SSH found** through tunnel:
   - Brutes it through the tunnel
   - On success: adds that host to the pivot queue to go **even deeper**
7. Repeats up to **5 hops deep** (`MAX_DEPTH = 5`) [Change it to your liking]

The chain looks like: `Your machine -> Host A -> Host B -> Host C`

Each SSH session stays open until all scanning through it completes, then closes cleanly.

---
---

### Step 8 - Pivot Mapper

**File:** `post/pivot_mapper.py`

- Runs `traceroute -n` to each live host
- Records intermediate hops (the route to get there)
- Checks which access protocols are available (SSH port 22, RDP 3389, WinRM 5985)
- Saves `pivot_map.txt` with the full topology: target -> via -> hops -> services

---
---

### Step 9 - Reporting

**Files:** `core/reporter.py`, `report/mysql_report.py`

Three report formats written to `<out_dir>/reports/`:
- `report.txt` - plain text findings summary
- `report.html` - styled HTML with a findings table sorted by severity
- `report.json` - full machine-readable output (good for later processing)
- `mysql_report.*` - dedicated MySQL findings breakdown

---
---

### Step 10 - Recursive Loop

After all phases finish, `main.py` checks:
- Did loot collection find any **leaked IPs** in config files?
- Did the pivot scanner discover any **new hosts** from deeper subnets?

If yes -> those new hosts are added to `ctx.scan_queue` and the whole process runs again on them.

Currently `max_rounds = 1` - bump to `2` or `3` in `main.py` for multi-hop recursive labs.

---
---

## Speed Profiles

Defined in `config.py`, selected with `--speed`:

| Profile | nmap Timing | Brute Force | Threads | Use When |
|---|---|---|---|---|
| `fast` | T4 | **OFF** | 10 | Quick recon, CTFs |
| `balanced` | T3 | ON | 20 | Normal lab work (USE THIS) |
| `deep` | T2 | ON | 30 | Full thorough test |

---
---

## Tools to Install

### System (apt)
```bash
sudo apt update && sudo apt install -y \
  nmap masscan hydra \
  metasploit-framework \
  gobuster ffuf \
  mysql-client \
  john hashcat \
  traceroute netcat-traditional \
  enum4linux smbclient \
  curl openssl dnsutils \
  snmp ldap-utils net-tools
```

### Python (pip3)
```bash
pip3 install --break-system-packages \
  paramiko \
  requests \
  mysql-connector-python \
  python-nmap \
  impacket \
  colorama \
  prettytable \
  jinja2
```

### Optional but useful
```bash
sudo apt install -y nikto wfuzz whatweb sslscan
```

---
---

## Configuration (`autopwn/config.py`)

Things to check before running:

| Setting | What it does |
|---|---|
| `WORDLIST_PASSWORDS` | Path to `passwords.txt` - **update if your username isn't `ubuntu_user`** |
| `WORDLIST_USERNAMES` | Path to `usernames.txt` - same |
| `WORDLIST_DIRS` | Path to `dirs.txt` for HTTP fuzzing |
| `SERVICE_PORTS` | Map of service -> ports used during scanning |
| `FALLBACK_PASSWORDS` | Short built-in list used if wordlist file not found |
| `MSF_MSSQL_MODULES` | Metasploit modules that auto-fire for MSSQL |
| `MSF_SMB_MODULES` | Metasploit modules that auto-fire for SMB |

> Wordlist paths are hardcoded to `/home/ubuntu_user/ris602/wordlists/` - change `ubuntu_user` to your actual username if different.

---
---

## Output Structure

Each run saves everything under `/tmp/autopwn_<timestamp>/`:

```
/tmp/autopwn_20260408_134500/
├── autopwn.log
├── reports/
│   ├── report.txt
│   ├── report.html
│   └── report.json
├── post/
│   ├── pivot_map.txt
│   └── pivot_scanner/
│       └── <host_ip>/
│           ├── subnets.txt              <- subnets visible from this host
│           ├── hydra_ssh_<ip>.txt       <- SSH brute results
│           └── <host>_mysql/
│               ├── instance/            <- version, users, privileges, plugins
│               ├── databases/
│               │   └── <dbname>/
│               │       ├── tables/
│               │       │   ├── <table>_data.txt   <- full row dump
│               │       │   └── <table>_count.txt
│               │       └── <dbname>_full.sql      <- mysqldump
│               └── sensitive_columns/   <- password/email/PII column search
└── discovery/
```

---
---

## Safe to Delete (empty stubs)

These folders exist but have no code in them:

```bash
rm -rf autopwn/services/smb/
rm -rf autopwn/services/ftp/
rm -rf autopwn/services/rdp/
rm -rf autopwn/services/dns/
rm -rf autopwn/services/nfs/
rm -rf autopwn/services/snmp/
rm -rf autopwn/services/ldap/
rm -rf autopwn/services/vpn/
bash rm_pycache.sh    # run before every git push
```

---
---

## .gitignore

```gitignore
__pycache__/
*.pyc
msf_results/
wordlists/hydra.restore
*.log
/tmp/
```

---
---

## Notes to Self

- **`max_rounds = 1`** in `main.py` line ~130 - change to `2` or `3` for multi-hop recursive scanning in larger labs
- **`MAX_DEPTH = 5`** and **`MAX_NEW_HOSTS = 50`** at the top of `pivot_scanner.py` - tune for your lab size
- **`--deep-pivot`** flag enables scanning of `via` (routed) subnets, not just directly connected ones - use in labs with routing between segments
- **`ctx.domain`** stays `None` until a DNS or LDAP module discovers it - or pass `--domain lab.local` manually if you know it upfront

---
---

*Last updated: April 2026 - RIS602 Lab*

---
---
## LICENSE
MIT
MIT
MIT
