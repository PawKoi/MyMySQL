import re, os
from core.executor import safe_run
from core.logger import get_logger
from core.utils import make_out_dir
from config import get_profile

def run(ctx):
    log = get_logger(); log.banner("SERVICE -- Generic Vulnerability Scan"); log.set_phase("vuln_scan")
    profile = get_profile()
    for host in sorted(ctx.live_hosts):
        ports = ctx.open_ports.get(host,{}).get("tcp",[])
        if not ports: continue
        out_dir = make_out_dir(ctx.out_dir, "services", "generic", host)
        port_arg = ",".join(str(p) for p in ports[:50])
        log.info(f"vuln scripts: {host} on {len(ports)} ports")
        rc, out, _ = safe_run(
            f"nmap --script vuln,exploit -p{port_arg} -{profile['nmap_timing']} {host} "
            f"--script-timeout 60s -oN {out_dir}/nmap_vuln.txt",
            timeout=profile["timeout_cmd"]*6, label=f"vuln-scan-{host}"
        )
        if "VULNERABLE" in out.upper():
            vulns = [l for l in out.splitlines() if "VULNERABLE" in l.upper() or "CVE" in l]
            ctx.add_finding("HIGH", host, f"nmap vuln scan: {len(vulns)} findings", "\n".join(vulns[:20]))
            for v in vulns[:5]:
                log.success(f"  VULN: {v.strip()}")
