from core.logger import get_logger
from core.utils import make_out_dir, grab_banner, port_is_open

def run(ctx):
    log = get_logger(); log.banner("SERVICE -- Generic Banner Grabbing"); log.set_phase("banner_grab")
    for host in sorted(ctx.live_hosts):
        ports = ctx.open_ports.get(host,{}).get("tcp",[])
        out_dir = make_out_dir(ctx.out_dir, "services", "generic", host)
        banners = {}
        for port in ports[:30]:
            banner = grab_banner(host, port, timeout=2.5)
            if banner:
                banners[port] = banner[:200]
                log.info(f"  {host}:{port} -> {banner[:60]}")
        if banners:
            content = "\n".join(f"Port {p}: {b}" for p, b in banners.items())
            with open(f"{out_dir}/banners.txt","w") as f: f.write(content)
            ctx.add_finding("INFO", host, f"Banners grabbed on {len(banners)} ports", content[:400])
