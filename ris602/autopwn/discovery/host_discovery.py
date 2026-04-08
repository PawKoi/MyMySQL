import os, re, socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.executor import safe_run
from core.logger import get_logger
from core.utils import expand_cidr, is_valid_ip, make_out_dir
from config import get_profile, tool_available

def run(ctx):
    log = get_logger(); log.banner("PHASE 1 -- Host Discovery"); log.set_phase("host_discovery")
    profile = get_profile(); out_dir = make_out_dir(ctx.out_dir, "discovery")
    all_hosts = set()
    exclude_ip = getattr(ctx, "exclude", None); targets = expand_cidr(ctx.target)
    log.info(f"Expanded target: {len(targets)} addresses")

    # 1. nmap ping sweep
    log.info("Technique 1: nmap ping sweep (-sn)...")
    rc, out, _ = safe_run(
        f"nmap -sn -{profile['nmap_timing']} --open {ctx.target} -oG {out_dir}/nmap_pingsweep.gnmap",
        timeout=profile["timeout_cmd"], label="nmap-pingsweep"
    )
    for line in out.splitlines():
        m = re.search(r"Host: (\d+\.\d+\.\d+\.\d+)", line)
        if m: all_hosts.add(m.group(1))
    log.info(f"  nmap sweep -> {len(all_hosts)} hosts so far")

    # 2. ARP scan (layer-2, bypasses ICMP filtering)
    if tool_available("arp-scan") and os.geteuid() == 0:
        log.info("Technique 2: arp-scan (layer-2)...")
        iface_flag = f"-I {ctx.iface}" if ctx.iface else ""
        rc, out, _ = safe_run(f"arp-scan {iface_flag} --localnet --ignoredups", timeout=60, label="arp-scan")
        for line in out.splitlines():
            m = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+", line)
            if m and is_valid_ip(m.group(1)): all_hosts.add(m.group(1))
        log.info(f"  arp-scan -> {len(all_hosts)} hosts so far")

    # 3. masscan sweep on top ports
    if tool_available("masscan") and os.geteuid() == 0:
        log.info("Technique 3: masscan port sweep...")
        mout = os.path.join(out_dir, "masscan_sweep.txt")
        rc, out, _ = safe_run(
            f"masscan {ctx.target} -p21,22,23,25,53,80,135,139,443,445,1433,3306,3389,8080 "
            f"--rate={profile['masscan_rate']} -oG {mout} --wait 2",
            timeout=120, label="masscan"
        )
        if rc == 0:
            for line in open(mout,"r",errors="replace") if os.path.exists(mout) else []:
                m = re.search(r"Host: (\d+\.\d+\.\d+\.\d+)", line)
                if m: all_hosts.add(m.group(1))
        log.info(f"  masscan -> {len(all_hosts)} hosts so far")

    # 4. TCP connect sweep (no root needed, fallback)
    log.info("Technique 4: TCP connect sweep (22,80,135,139,443,445,1433,3389)...")
    ports = [22,80,135,139,443,445,1433,3389,8080]
    def tcp_probe(ip):
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((ip, port))
                s.recv(1)
                s.close()
                return ip
            except socket.timeout:
                pass
            except ConnectionRefusedError:
                pass
            except Exception:
                pass
        return None
    with ThreadPoolExecutor(max_workers=min(50, profile["threads"]*3)) as ex:
        futs = {ex.submit(tcp_probe, ip): ip for ip in targets}
        for fut in as_completed(futs):
            r = fut.result()
            if r: all_hosts.add(r)
    log.info(f"  TCP connect -> {len(all_hosts)} hosts so far")

    # 5. nmap ICMP probe
    log.info("Technique 5: nmap ICMP echo probe...")
#     rc, out, _ = safe_run(f"nmap -sn -PE --send-ip {ctx.target}", timeout=60, label="nmap-icmp")
    for line in out.splitlines():
        m = re.search(r"Nmap scan report for (?:\S+ \()?(\d+\.\d+\.\d+\.\d+)", line)
        if m: all_hosts.add(m.group(1))

    for exc in (getattr(ctx, "exclude", "") or "").split(","):
        all_hosts.discard(exc.strip())
    ctx.live_hosts = all_hosts
    with open(os.path.join(out_dir,"live_hosts.txt"),"w") as f:
        f.write("\n".join(sorted(all_hosts)))
    log.success(f"Discovery complete: {len(all_hosts)} live hosts -> {sorted(all_hosts)}")
    for h in all_hosts:
        ctx.add_finding("INFO", h, "Host alive", "Multi-technique sweep")
