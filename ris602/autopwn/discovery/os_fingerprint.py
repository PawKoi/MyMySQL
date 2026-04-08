import re, socket
from core.executor import safe_run
from core.logger import get_logger
from core.utils import make_out_dir, grab_banner
from config import get_profile

def run(ctx):
    log = get_logger(); log.banner("PHASE 2b -- OS Fingerprinting"); log.set_phase("os_fingerprint")
    profile = get_profile(); out_dir = make_out_dir(ctx.out_dir, "osfingerprint")
    for host in sorted(ctx.live_hosts):
        log.info(f"OS fingerprint: {host}")
        scores = {}

        # Technique 1: nmap OS detection
        rc, out, _ = safe_run(
            f"nmap -O --osscan-guess -{profile['nmap_timing']} {host}",
            timeout=90, label=f"nmap-os-{host}"
        )
        m = re.search(r"(?:OS:|Running:|OS details:)\s*(.+)", out, re.IGNORECASE)
        if m: scores[m.group(1).strip()] = scores.get(m.group(1).strip(), 0) + 3

        # Technique 2: TTL analysis via ping
        rc2, out2, _ = safe_run(f"ping -c 3 -W 1 {host}", timeout=10, label=f"ping-ttl-{host}")
        ttl_m = re.search(r"ttl=(\d+)", out2, re.IGNORECASE)
        if ttl_m:
            ttl = int(ttl_m.group(1))
            if ttl <= 64: scores["Linux/Unix"] = scores.get("Linux/Unix",0)+1
            elif ttl <= 128: scores["Windows"] = scores.get("Windows",0)+1
            else: scores["Network Device"] = scores.get("Network Device",0)+1

        # Technique 3: SMB banner (Windows specific)
        ports = ctx.open_ports.get(host, {}).get("tcp", [])
        if 445 in ports:
            rc3, out3, _ = safe_run(
                f"nmap --script smb-os-discovery -{profile['nmap_timing']} -p445 {host}",
                timeout=60, label=f"smb-os-{host}"
            )
            if "Windows" in out3:
                m3 = re.search(r"OS:\s*(.+)", out3)
                if m3: scores[m3.group(1).strip()] = scores.get(m3.group(1).strip(), 0) + 2

        # Technique 4: SSH banner
        if 22 in ports:
            banner = grab_banner(host, 22, timeout=3.0)
            if "Ubuntu" in banner: scores["Linux (Ubuntu)"] = scores.get("Linux (Ubuntu)",0)+2
            elif "Debian" in banner: scores["Linux (Debian)"] = scores.get("Linux (Debian)",0)+2
            elif "OpenSSH" in banner: scores["Linux/Unix"] = scores.get("Linux/Unix",0)+1

        # Technique 5: HTTP Server header
        if 80 in ports or 8080 in ports:
            port = 80 if 80 in ports else 8080
            rc5, out5, _ = safe_run(f"curl -s -I --max-time 5 http://{host}:{port}", timeout=10, label=f"http-hdr-{host}")
            m5 = re.search(r"Server:\s*(.+)", out5, re.IGNORECASE)
            if m5:
                srv = m5.group(1).strip()
                if "IIS" in srv: scores["Windows (IIS)"] = scores.get("Windows (IIS)",0)+2
                elif "Apache" in srv: scores["Linux (Apache)"] = scores.get("Linux (Apache)",0)+1

        best = max(scores, key=scores.get) if scores else "Unknown"
        ctx.os_map[host] = best
        log.success(f"  {host} -> {best} (scores: {scores})")
        ctx.add_finding("INFO", host, f"OS Fingerprint: {best}", str(scores))
