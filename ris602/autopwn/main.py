#!/usr/bin/env python3
from core.utils import expand_cidr
"""
AutoPwn -- Automated Penetration Testing Framework

Works against ANY target on ANY network.
Domain/FQDN is auto-discovered from live DNS/LDAP servers.
You can also supply it manually with --domain.

Examples:
  sudo python3 main.py --target 10.0.0.0/24
  sudo python3 main.py --target 192.168.1.50
  sudo python3 main.py --target 10.10.10.0/25 --domain company.local
  sudo python3 main.py --target 10.0.0.0/24   --speed deep --no-brute
"""
import argparse, sys, os, threading, time, traceback
from datetime import datetime
from collections import deque

def print_animated_banner():
    """Print an animated, colorful 'My My' banner"""
    
    # Clear screen and move to top
    sys.stdout.write('\033[2J\033[H')
    sys.stdout.flush()
    
    # ANSI color codes
    colors = [
        '\033[91m',  # Bright Red
        '\033[93m',  # Bright Yellow
        '\033[92m',  # Bright Green
        '\033[96m',  # Bright Cyan
        '\033[94m',  # Bright Blue
        '\033[95m',  # Bright Magenta
    ]
    
    # Clear, readable "MY MY" banner
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║     ███╗   ███╗██╗   ██╗     ███╗   ███╗██╗   ██╗      ║
    ║     ████╗ ████║╚██╗ ██╔╝     ████╗ ████║╚██╗ ██╔╝      ║
    ║     ██╔████╔██║ ╚████╔╝      ██╔████╔██║ ╚████╔╝       ║
    ║     ██║╚██╔╝██║  ╚██╔╝       ██║╚██╔╝██║  ╚██╔╝        ║
    ║     ██║ ╚═╝ ██║   ██║        ██║ ╚═╝ ██║   ██║         ║
    ║     ╚═╝     ╚═╝   ╚═╝        ╚═╝     ╚═╝   ╚═╝         ║
    ║                                                          ║
    ║                        MyMySQL                           ║
    ╚══════════════════════════════════════════════════════════╝
    """
    
    # Animate each line with color cycling
    lines = banner.split('\n')
    
    for i, line in enumerate(lines):
        if line.strip():  # Only animate non-empty lines
            for color in colors:
                sys.stdout.write('\r' + color + line + '\033[0m')
                sys.stdout.flush()
                time.sleep(0.03)
            sys.stdout.write('\n')
        else:
            sys.stdout.write('\n')
        time.sleep(0.05)
    
    # Add a flashing/spinning effect to the title
    title_line = "                  ✪ MY MY AUTO-PWN ✪                     "
    for _ in range(5):
        for color in ['\033[91m', '\033[93m', '\033[92m', '\033[96m', '\033[95m']:
            sys.stdout.write('\r' + color + title_line + '\033[0m')
            sys.stdout.flush()
            time.sleep(0.1)
    
    print("\n" + "═" * 58)
    print("\033[90m" + datetime.now().strftime("⚡ STARTED: %Y-%m-%d @ %H:%M:%S") + "\033[0m")
    print("═" * 58 + "\n")
    time.sleep(0.3)

class Context:
    def __init__(self, target, out_dir, iface=None, no_brute=False, exclude=None,
                 domain=None):
        self.target      = target
        self.out_dir     = out_dir
        self.iface       = iface
        self.no_brute    = no_brute
        # domain: None until dns_enum or ldap_enum discovers it live.
        # Can also be pre-seeded via --domain flag.
        self.domain      = domain
        self.exclude     = exclude
        self.deep_pivot  = False
        self.start_time  = datetime.now().isoformat(timespec="seconds")
        self.live_hosts  = set()
        self.open_ports  = {}   # {host: {tcp:[...], udp:[...]}}
        self.service_map = {}   # {host: {port: {service, version}}}
        self.os_map      = {}   # {host: "Windows/Linux/..."}
        self.evasion_map = {}   # {host: {fw_type, waf, engine_cfg}}
        self.findings    = []   # [{severity, host, title, detail, ts}]
        self.loot        = {}   # {credentials, hashes, rce, users, dns_records, ...}
        self._lock       = threading.Lock()
        # NEW for recursion
        self.scan_queue  = deque()
        self.seen_hosts  = set()

    def add_finding(self, severity, host, title, detail=""):
        with self._lock:
            self.findings.append({
                "severity": severity.upper(),
                "host":     host,
                "title":    title,
                "detail":   str(detail)[:1000],
                "ts":       datetime.now().isoformat(timespec="seconds"),
            })

    def set_domain(self, domain):
        """Called when domain is discovered live from the target."""
        with self._lock:
            if domain and not self.domain:
                self.domain = domain.strip().lower()
                from core.logger import get_logger
                get_logger().success(f"Domain auto-discovered: {self.domain}")

class ProgressBar:
    def __init__(self):
        self._pct  = 0
        self._msg  = "Starting..."
        self._stop = False
        self._t    = threading.Thread(target=self._render, daemon=True)

    def start(self): self._t.start()

    def update(self, pct, msg):
        self._pct = min(int(pct), 100)
        self._msg = msg

    def stop(self):
        self._stop = True
        self._t.join(timeout=2)

    def _render(self):
        bar_len = 40
        while not self._stop:
            filled = int(bar_len * self._pct / 100)
            bar = "█" * filled + "░" * (bar_len - filled)
            line = (f"\r\x1b[92m[{bar}]\x1b[0m "
                    f"\x1b[96m{self._pct:3d}%\x1b[0m"
                    f"  \x1b[90m{self._msg[:60]}\x1b[0m    ")
            sys.stdout.write(line); sys.stdout.flush()
            time.sleep(0.15)
        sys.stdout.write("\n"); sys.stdout.flush()

def run_phase(label, fn, ctx, pb, current_pct, weight):
    try:
        from core.logger import get_logger
        log = get_logger()
        pb.update(current_pct, f"Running | {label}")
        log.info(f">>> Phase: {label}")
        fn(ctx)
        pb.update(current_pct + weight, f"Done    | {label}")
        log.success(f"<<< Done: {label}")
    except KeyboardInterrupt:
        raise
    except Exception as e:
        from core.logger import get_logger
        get_logger().error(f"Phase ERROR [{label}]: {e}\n{traceback.format_exc()[:400]}")
        ctx.add_finding("ERROR", "framework", f"Phase failed: {label}", str(e))

def is_valid_ip(ip):
    """Trivial inline version for main loop."""
    try:
        [int(x) for x in ip.split(".")]
        if not 0 < len(ip.split(".")) == 4:
            return False
        return True
    except:
        return False

def main():
    # Print animated banner FIRST
    print_animated_banner()
    
    parser = argparse.ArgumentParser(
        description="AutoPwn -- Generic automated pentest framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--target",     required=True,
                        help="IP, CIDR, hostname, or range (e.g. 10.0.0.0/24, 192.168.1.1-20)")
    parser.add_argument("--domain",     default=None,
                        help="Domain hint e.g. company.local (auto-detected if omitted)")
    parser.add_argument("--out",        default=None,
                        help="Output directory (default: /tmp/autopwn_<timestamp>)")
    parser.add_argument("--iface",      default=None,
                        help="Network interface for ARP scan (e.g. eth0, ens33)")
    parser.add_argument("--no-brute",   action="store_true",
                        help="Disable all brute force modules")
    parser.add_argument("--deep-pivot", action="store_true", help="Also scan via/routed subnets, not just directly connected")
    parser.add_argument("--exclude", default="", help="Comma-separated IPs to exclude e.g. 1.2.3.4,1.2.3.5")
    parser.add_argument("--speed",      default="fast",
                        choices=["fast","balanced","deep"],
                        help="Scan speed: fast (T4, no brute) | balanced (T3) | deep (T2, full)")
    args = parser.parse_args()

    os.environ["AUTOPWN_SPEED"] = args.speed

    ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = args.out or f"/tmp/autopwn_{ts}"
    os.makedirs(out_dir, exist_ok=True)

    from core.logger import init_logger
    log = init_logger(out_dir)

    ctx = Context(
        target=args.target, out_dir=out_dir, iface=args.iface,
        no_brute=args.no_brute,
        domain=args.domain,
        exclude=args.exclude,
    )

    ctx.deep_pivot = args.deep_pivot
    log.info(f"Deep pivot mode: {ctx.deep_pivot}")

    if args.no_brute:
        import config
        for k in config.PROFILES:
            config.PROFILES[k]["brute_enabled"] = False

    log.banner(f"AutoPwn -- Target: {args.target}")
    log.info(f"Output : {out_dir}")
    log.info(f"Speed  : {args.speed}  |  Brute: {'OFF' if args.no_brute else 'ON'}")
    if args.domain:
        log.info(f"Domain : {args.domain}  (user-supplied)")
    else:
        log.info("Domain : not set -- will auto-detect from DNS/LDAP responses")

    pb = ProgressBar(); pb.start()

    from discovery        import host_discovery, port_scanner
    from post             import loot_collector, pivot_scanner
    from services.mysql   import mysql_brute, mysql_exploit
    from services.ssh     import ssh_brute
    from core             import reporter

    def _report(ctx):
        txt  = reporter.generate_txt_report(ctx)
        html = reporter.generate_html_report(ctx)
        jsn  = reporter.generate_json_report(ctx)
        from report import mysql_report; mysql_report.run(ctx)
        log.success(f"Reports written to {out_dir}/reports/")

    phases = [
        (5,  "MySQL Brute",        mysql_brute.run),
        (5,  "MySQL Exploit",      mysql_exploit.run),
        (5,  "SSH Brute",          ssh_brute.run),
        (3,  "Loot Collection",    loot_collector.run),
        (0,  "Pivot Scanner",      pivot_scanner.run),
        (3,  "Reporting",          _report),
    ]

    total_weight = sum(w for w,_,_ in phases)

    # NEW: recursion loop

    # Start queue with initial target expansion
    initial_hosts = []
    for ip in expand_cidr(ctx.target):
        if is_valid_ip(ip):
            initial_hosts.append(ip)
    ctx.scan_queue = deque(initial_hosts)
    ctx.seen_hosts = set(ctx.live_hosts)

    # Control how many passes (stop if exploding)
    max_rounds = 1
    round_num = 0

    while ctx.scan_queue and round_num < max_rounds:
        round_num += 1
        log.info(f"Recursive round {round_num}, queue size {len(ctx.scan_queue)}")

        # --- 1. Host discovery over the current queue contents (one big sweep) ---
        ctx.live_hosts.clear()
        run_phase("Host Discovery", host_discovery.run, ctx, pb, 0, 5)

        # --- 2. Port scan what we found ---
        ctx.open_ports.clear()
        ctx.service_map.clear()
        run_phase("Port Scanning", port_scanner.run, ctx, pb, 5, 5)

        # --- 3. Run all non-discovery phases on updated ctx ---
        current_pct = 10
        for weight, label, fn in phases:
            if "Host Discovery" in label or "Port Scanning" in label:
                continue
            run_phase(label, fn, ctx, pb, current_pct, weight)
            current_pct += weight

        # --- 4. Harvest new hosts from loot and pivots ---
        new_hosts = set()

        # From leaked IPs (loot_collector)
        leaked_ips = ctx.loot.get("leaked_ips", [])
        for ip in leaked_ips:
            if is_valid_ip(ip) and ip not in ctx.live_hosts and ip not in ctx.seen_hosts:
                new_hosts.add(ip)

        # From pivot_candidates (e.g. MySQL lateral users)
        for p in ctx.loot.get("pivot_candidates", []):
            h = p.get("host")
            if h and is_valid_ip(h) and h not in ctx.seen_hosts:
                new_hosts.add(h)

        for p in ctx.loot.get("pivot_paths", []):
            for h in [p.get("target"), p.get("pivot_via")]:
                if h and is_valid_ip(h) and h not in ctx.seen_hosts:
                    new_hosts.add(h)

        # Queue new hosts and mark seen
        for h in new_hosts:
            if h not in ctx.seen_hosts:
                ctx.scan_queue.append(h)
                ctx.seen_hosts.add(h)

        log.info(f"Recursive round {round_num} done; {len(new_hosts)} new hosts added")

    # --- 5. Final report after recursion ---
    pb.update(100, "Complete!")
    time.sleep(0.4); pb.stop()

    log.banner("AutoPwn Complete!")
    sev_count = {}
    for f in ctx.findings:
        sev_count[f["severity"]] = sev_count.get(f["severity"], 0) + 1
    log.success(f"Findings: {len(ctx.findings)} total")
    for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO","ERROR"]:
        if s in sev_count: log.success(f"  {s}: {sev_count[s]}")
    log.success(f"Credentials found : {len(ctx.loot.get('credentials',[]))}")
    log.success(f"Domain identified : {ctx.domain or 'none detected'}")
    log.success(f"Output            : {out_dir}")

if __name__ == "__main__":
    main()