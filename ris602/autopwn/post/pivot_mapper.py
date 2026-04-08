import re
from core.executor import safe_run
from core.logger import get_logger
from core.utils import make_out_dir, extract_ips
from config import get_profile

def run(ctx):
    log = get_logger(); log.banner("POST -- Pivot Path Mapping"); log.set_phase("pivot_map")
    out_dir = make_out_dir(ctx.out_dir, "post")
    pivots = []

    for host in ctx.live_hosts:
        ports = ctx.open_ports.get(host,{}).get("tcp",[])
        routes = []

        # Traceroute to find intermediate hops
        rc, out, _ = safe_run(f"traceroute -n -m 10 {host}", timeout=20, label=f"traceroute-{host}")
        hops = extract_ips(out)
        if len(hops) > 1:
            routes = hops[:-1]  # All hops except target itself

        # Route table if we have shell
        pivot_ports = {"ssh":22,"rdp":3389,"winrm":5985}
        accessible = {svc: port for svc,port in pivot_ports.items() if port in ports}

        if accessible:
            entry = {
                "target": host,
                "pivot_via": routes[-1] if routes else "direct",
                "services": list(accessible.keys()),
                "hops": routes,
            }
            pivots.append(entry)
            log.success(f"  Pivot candidate: {host} via {entry['pivot_via']} using {list(accessible.keys())}")
            ctx.add_finding("INFO", host, f"Pivot path: {' -> '.join(routes + [host])}", str(accessible))

    ctx.loot["pivot_paths"] = pivots
    with open(f"{out_dir}/pivot_map.txt","w") as f:
        for p in pivots:
            f.write(f"Target: {p['target']}\n  Via: {p['pivot_via']}\n  Services: {p['services']}\n  Hops: {p['hops']}\n\n")
    log.success(f"Pivot mapping complete: {len(pivots)} candidates")
