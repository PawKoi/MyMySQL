import os
from core.logger import get_logger
from core.utils import make_out_dir, extract_credentials, extract_hashes, extract_ips, read_file

def run(ctx):
    log = get_logger(); log.banner("POST -- Loot Collection"); log.set_phase("loot_collect")
    out_dir = make_out_dir(ctx.out_dir, "loot")

    # Build dedup sets from already-known loot
    cred_keys = {f"{c.get('user','')}:{c.get('password','')}"
                 for c in ctx.loot.get("credentials",[])}
    hash_set   = set(ctx.loot.get("hashes",[]))
    ip_set     = set(ctx.loot.get("leaked_ips",[]))

    for root, dirs, fnames in os.walk(ctx.out_dir):
        if any(skip in root for skip in ["loot","reports"]): continue
        for fname in fnames:
            if not fname.endswith((".txt",".xml",".json",".yaml")): continue
            fpath = os.path.join(root, fname)
            content = read_file(fpath)
            if not content or len(content) < 5: continue

            for c in extract_credentials(content):
                key = f"{c.get('user','')}:{c.get('password','')}"
                if key not in cred_keys and c.get("user"):
                    cred_keys.add(key)
                    c["source_file"] = os.path.relpath(fpath, ctx.out_dir)
                    ctx.loot.setdefault("credentials",[]).append(c)
                    log.success(f"  Loot cred: {c['user']}:{c['password']} ({fname})")

            for h in extract_hashes(content):
                if h not in hash_set:
                    hash_set.add(h)
                    ctx.loot.setdefault("hashes",[]).append(h)

            for ip in extract_ips(content):
                if ip not in ctx.live_hosts and ip not in ip_set:
                    # Only private ranges
                    if any(ip.startswith(p) for p in ("10.","172.","192.168.")):
                        ip_set.add(ip)
                        ctx.loot.setdefault("leaked_ips",[]).append(ip)

    creds  = ctx.loot.get("credentials",[])
    hashes = ctx.loot.get("hashes",[])
    leaked = ctx.loot.get("leaked_ips",[])

    if creds:
        with open(os.path.join(out_dir,"credentials.txt"),"w") as f:
            for c in creds:
                f.write(f"[{c.get('service','?'):<8}] {c.get('host','?'):<18} "
                        f"{c.get('user','?')}:{c.get('password','?')}\n")
        log.success(f"  {len(creds)} credentials -> loot/credentials.txt")
    if hashes:
        with open(os.path.join(out_dir,"hashes.txt"),"w") as f: f.write("\n".join(hashes))
        log.success(f"  {len(hashes)} hashes -> loot/hashes.txt")
    if leaked:
        with open(os.path.join(out_dir,"leaked_ips.txt"),"w") as f: f.write("\n".join(leaked))
        log.success(f"  {len(leaked)} leaked IPs -> loot/leaked_ips.txt")

    log.success(f"Loot: {len(creds)} creds | {len(hashes)} hashes | {len(leaked)} leaked IPs")
