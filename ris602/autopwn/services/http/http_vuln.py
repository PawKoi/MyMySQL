import os
from core.executor import safe_run
from core.logger import get_logger
from core.utils import make_out_dir
from config import get_profile, tool_available

def run(ctx):
    log = get_logger(); log.banner("SERVICE -- HTTP Vulnerability Checks"); log.set_phase("http_vuln")
    profile = get_profile()
    for host in ctx.live_hosts:
        ports = ctx.open_ports.get(host,{}).get("tcp",[])
        web_ports = [(p,"https" if p in [443,8443] else "http") for p in ports if p in [80,443,8080,8443,8000]]
        if not web_ports: continue
        out_dir = make_out_dir(ctx.out_dir, "services", "http", host)

        for port, scheme in web_ports[:2]:
            url = f"{scheme}://{host}:{port}"
            log.info(f"HTTP vuln scan: {url}")

            # sqlmap
            if tool_available("sqlmap"):
                rc, out, _ = safe_run(
                    f"sqlmap -u {url}/?id=1 --batch --level=2 --risk=2 --timeout=10 "
                    f"--output-dir={out_dir}/sqlmap_{port} --forms --crawl=2",
                    timeout=profile["timeout_cmd"]*4, label=f"sqlmap-{host}-{port}"
                )
                if "injectable" in out.lower() or "sqlmap identified" in out.lower():
                    ctx.add_finding("CRITICAL", host, f"SQLi vulnerability on {url}", out[:500])
                    log.success(f"  SQL injection found on {url}")

            # nmap http vuln scripts
            rc2, out2, _ = safe_run(
                f"nmap --script http-shellshock,http-phpmyadmin-dir-traversal,http-vuln-cve2017-5638,"
                f"http-vuln-cve2014-8877,http-put,http-methods -p{port} {host}",
                timeout=90, label=f"nmap-http-vuln-{host}-{port}"
            )
            with open(os.path.join(out_dir,f"nmap_http_vuln_{port}.txt"),"w") as f: f.write(out2)
            if "VULNERABLE" in out2.upper():
                ctx.add_finding("HIGH", host, f"nmap HTTP vuln detected on :{port}", out2[:500])

            # CORS check
            rc3, out3, _ = safe_run(
                f"curl -sk -H 'Origin: https://evil.com' -I {url}",
                timeout=10, label=f"cors-{host}-{port}"
            )
            if "access-control-allow-origin: *" in out3.lower() or "access-control-allow-origin: https://evil.com" in out3.lower():
                ctx.add_finding("MEDIUM", host, f"CORS misconfiguration on :{port}", out3[:300])
