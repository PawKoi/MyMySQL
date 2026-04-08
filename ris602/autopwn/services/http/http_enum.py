import re, os
from core.executor import safe_run
from core.logger import get_logger
from core.utils import make_out_dir
from config import get_profile, tool_available

INTERESTING_APPS = ["WordPress","Drupal","Joomla","phpMyAdmin","Jenkins","Tomcat","WebLogic",
                    "GitLab","Grafana","Kibana","Splunk","Exchange","SharePoint"]

def run(ctx):
    log = get_logger(); log.banner("SERVICE -- HTTP Enumeration"); log.set_phase("http_enum")
    profile = get_profile()
    for host in ctx.live_hosts:
        ports = ctx.open_ports.get(host,{}).get("tcp",[])
        web_ports = [(p,"https" if p in [443,8443] else "http")
                     for p in ports if p in [80,443,8080,8443,8000,8888,8008]]
        if not web_ports: continue
        out_dir = make_out_dir(ctx.out_dir, "services", "http", host)

        for port, scheme in web_ports:
            url = f"{scheme}://{host}:{port}"
            log.info(f"HTTP enum: {url}")

            # 1. Headers
            rc, head, _ = safe_run(f"curl -sk -I --max-time 8 {url}",
                                   timeout=12, label=f"curl-head-{host}-{port}")
            with open(os.path.join(out_dir,f"headers_{port}.txt"),"w") as f: f.write(head)
            _check_security_headers(ctx, host, port, head)

            # 2. robots.txt / sitemap / security.txt
            for path in ["/robots.txt","/sitemap.xml","/.well-known/security.txt"]:
                rc2, body, _ = safe_run(f"curl -sk --max-time 6 {url}{path}",
                                        timeout=10, label=f"curl-{path.lstrip('/')}-{host}")
                if body.strip() and len(body) > 20 and "<html" not in body[:50].lower():
                    fname = path.strip("/").replace("/","_") + f"_{port}.txt"
                    with open(os.path.join(out_dir, fname),"w") as f: f.write(body)
                    ctx.add_finding("INFO", host, f"Found {path} on :{port}", body[:300])
                    if path=="/robots.txt":
                        disallowed = re.findall(r"(?i)Disallow:\s*(\S+)", body)
                        if disallowed:
                            log.success(f"  robots.txt Disallow: {disallowed[:5]}")

            # 3. nikto
            if tool_available("nikto"):
                nikto_out = os.path.join(out_dir, f"nikto_{port}.txt")
                safe_run(f"nikto -h {url} -timeout 5 -maxtime 120 -nointeractive -output {nikto_out}",
                         timeout=180, label=f"nikto-{host}-{port}")
                if os.path.isfile(nikto_out):
                    nd = open(nikto_out, errors="replace").read()
                    count = nd.count("OSVDB") + nd.count("CVE-")
                    if count:
                        ctx.add_finding("MEDIUM", host, f"Nikto: {count} issues on :{port}", nd[:600])
                        log.success(f"  Nikto {count} findings on {url}")

            # 4. whatweb
            if tool_available("whatweb"):
                rc4, ww, _ = safe_run(f"whatweb -a 3 --colour=never {url}",
                                      timeout=30, label=f"whatweb-{host}-{port}")
                with open(os.path.join(out_dir,f"whatweb_{port}.txt"),"w") as f: f.write(ww)
                if ww.strip():
                    ctx.add_finding("INFO", host, f"Tech stack :{port}", ww[:400])
                    for app in INTERESTING_APPS:
                        if app.lower() in ww.lower():
                            ctx.add_finding("MEDIUM", host, f"Detected: {app} on :{port}", ww[:200])
                            log.success(f"  Found {app} on {url}")

def _check_security_headers(ctx, host, port, headers):
    checks = {
        "Strict-Transport-Security":"Missing HSTS",
        "X-Frame-Options":"Missing X-Frame-Options (clickjacking)",
        "X-Content-Type-Options":"Missing X-Content-Type-Options",
        "Content-Security-Policy":"Missing Content-Security-Policy",
    }
    missing = [msg for hdr,msg in checks.items() if hdr.lower() not in headers.lower()]
    if missing:
        ctx.add_finding("LOW", host, f"Missing security headers :{port}", "\n".join(missing))
    m = re.search(r"(?i)^Server:\s*(.+)", headers, re.MULTILINE)
    if m: ctx.add_finding("LOW", host, f"Server version disclosure: {m.group(1).strip()}", "")
    for hdr in ["X-Powered-By","X-AspNet-Version","X-AspNetMvc-Version"]:
        m2 = re.search(rf"(?i)^{hdr}:\s*(.+)", headers, re.MULTILINE)
        if m2: ctx.add_finding("LOW", host, f"{hdr}: {m2.group(1).strip()}", "")
