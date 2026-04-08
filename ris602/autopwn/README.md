## File & Folder Reference

```
ris602/
│
├── run.sh                      ← MAIN ENTRY POINT - run this
├── excluded_run.sh             ← Same as run.sh but pre-configured excludes (REMOVED/IRRELEVANT)
├── admin_scan.sh               ← Admin-focused variant (REMOVED/IRRELEVANT)
├── private_scan.sh             ← For internal/private network ranges (REMOVED/IRRELEVANT)
├── private_scan_deep.sh        ← Slower, more thorough internal scan (REMOVED/IRRELEVANT)
├── private_scan_router.sh      ← Targets the gateway/router specifically (REMOVED/IRRELEVANT)
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
