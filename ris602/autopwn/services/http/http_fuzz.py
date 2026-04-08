import os
from core.executor import safe_run
from core.logger import get_logger
from core.utils import make_out_dir
from config import get_profile, tool_available, get_dir_wordlist, WORDLIST_VHOSTS

def run(ctx):
    log = get_logger(); log.banner("SERVICE -- HTTP Directory/VHost Fuzzing"); log.set_phase("http_fuzz")
    profile = get_profile(); wl = get_dir_wordlist()
    for host in ctx.live_hosts:
        ports = ctx.open_ports.get(host,{}).get("tcp",[])
        web_ports = [(p,"https" if p in [443,8443] else "http") for p in ports if p in [80,443,8080,8443,8000]]
        if not web_ports: continue
        out_dir = make_out_dir(ctx.out_dir, "services", "http", host)

        for port, scheme in web_ports[:2]:
            url = f"{scheme}://{host}:{port}"
            log.info(f"HTTP fuzz: {url}")

            # gobuster dir
            if tool_available("gobuster"):
                rc, out, _ = safe_run(
                    f"gobuster dir -u {url} -w {wl} -k -q -t 20 --timeout 5s "
                    f"-o {out_dir}/gobuster_{port}.txt",
                    timeout=profile["timeout_cmd"]*3, label=f"gobuster-{host}-{port}"
                )
                if os.path.exists(os.path.join(out_dir,f"gobuster_{port}.txt")):
                    found = [l for l in open(os.path.join(out_dir,f"gobuster_{port}.txt")).readlines() if "(Status:" in l]
                    if found:
                        ctx.add_finding("INFO", host, f"Gobuster found {len(found)} paths on :{port}", "".join(found[:20]))

            # ffuf if available
            elif tool_available("ffuf"):
                rc2, out2, _ = safe_run(
                    f"ffuf -u {url}/FUZZ -w {wl} -k -c -t 20 -timeout 5 -mc 200,301,302,401,403 "
                    f"-o {out_dir}/ffuf_{port}.json -of json -s",
                    timeout=profile["timeout_cmd"]*3, label=f"ffuf-{host}-{port}"
                )
