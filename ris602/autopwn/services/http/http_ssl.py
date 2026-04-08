import re, os
from core.executor import safe_run
from core.logger import get_logger
from core.utils import make_out_dir
from config import get_profile, tool_available

def run(ctx):
    log = get_logger(); log.banner("SERVICE -- SSL/TLS Analysis"); log.set_phase("http_ssl")
    profile = get_profile()
    for host in ctx.live_hosts:
        ports = ctx.open_ports.get(host,{}).get("tcp",[])
        ssl_ports = [p for p in ports if p in [443,8443,636,3269,465,993,995]]
        if not ssl_ports: continue
        out_dir = make_out_dir(ctx.out_dir, "services", "http", host)

        for port in ssl_ports:
            log.info(f"SSL analysis: {host}:{port}")

            # openssl cert info
            if tool_available("openssl"):
                rc, out, _ = safe_run(
                    f"openssl s_client -connect {host}:{port} -servername {host} </dev/null",
                    timeout=15, label=f"openssl-{host}-{port}"
                )
                with open(os.path.join(out_dir,f"ssl_cert_{port}.txt"),"w") as f: f.write(out)
                if "self-signed" in out.lower():
                    ctx.add_finding("LOW", host, f"Self-signed cert on :{port}", "")
                exp_m = re.search(r"Not After\s*:\s*(.+)", out)
                if exp_m: log.info(f"  Cert expires: {exp_m.group(1).strip()}")

                # Check for old TLS versions
                for proto in ["ssl2","ssl3","tls1","tls1_1"]:
                    rc2, out2, err2 = safe_run(
                        f"openssl s_client -{proto} -connect {host}:{port} </dev/null",
                        timeout=8, label=f"tls-{proto}-{host}-{port}"
                    )
                    if "CONNECTED" in out2 and "error" not in err2.lower():
                        ctx.add_finding("HIGH", host, f"Deprecated TLS/{proto} accepted on :{port}", "")
                        log.success(f"  {host}:{port} accepts deprecated {proto}")

            # testssl.sh
            if tool_available("testssl"):
                rc3, out3, _ = safe_run(
                    f"testssl --quiet --color 0 {host}:{port}",
                    timeout=180, label=f"testssl-{host}-{port}"
                )
                with open(os.path.join(out_dir,f"testssl_{port}.txt"),"w") as f: f.write(out3)
                if "CRITICAL" in out3 or "HIGH" in out3:
                    ctx.add_finding("HIGH", host, f"testssl HIGH/CRITICAL findings on :{port}", out3[:600])
