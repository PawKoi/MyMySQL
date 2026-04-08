import os
from core.executor import safe_run
from core.logger import get_logger
from core.utils import make_out_dir
from config import tool_available, get_password_wordlist

def run(ctx):
    log = get_logger(); log.banner("POST -- Hash Cracking"); log.set_phase("hash_crack")
    hashes = ctx.loot.get("hashes", [])
    if not hashes: log.info("No hashes to crack"); return
    out_dir = make_out_dir(ctx.out_dir, "loot")
    hash_file = os.path.join(out_dir, "hashes_to_crack.txt")
    with open(hash_file,"w") as f: f.write("\n".join(hashes))
    wl = get_password_wordlist()

    cracked_file = os.path.join(out_dir, "cracked.txt")
    if tool_available("john"):
        rc, out, _ = safe_run(
            f"john {hash_file} --wordlist={wl} --rules=Jumbo --pot={cracked_file}",
            timeout=300, label="john"
        )
        log.info(f"John output: {out[:200]}")
        # Show cracked
        rc2, out2, _ = safe_run(f"john {hash_file} --show --pot={cracked_file}", timeout=10, label="john-show")
        if out2.strip():
            ctx.add_finding("HIGH", "loot", f"Hashes cracked by John", out2[:400])
            log.success(f"  Cracked: {out2[:300]}")
        return

    if tool_available("hashcat"):
        for mode in ["0","1000","5600"]:  # md5, ntlm, netntlmv2
            rc, out, _ = safe_run(
                f"hashcat -m {mode} {hash_file} {wl} -o {cracked_file} --force --quiet",
                timeout=300, label=f"hashcat-m{mode}"
            )
            if os.path.exists(cracked_file) and os.path.getsize(cracked_file) > 0:
                cracked = open(cracked_file).read()
                ctx.add_finding("HIGH", "loot", f"Hashcat mode {mode} cracked hashes", cracked[:400])
                log.success(f"  Hashcat cracked: {cracked[:200]}")
                break
