import os, re, json
from core.executor import safe_run
from core.logger import get_logger
from core.utils import make_out_dir
from config import get_profile, tool_available, SERVICE_PORTS

def run(ctx):
    log = get_logger(); log.banner("PHASE 2 -- Port Scanning"); log.set_phase("port_scan")
    profile = get_profile(); out_dir = make_out_dir(ctx.out_dir, "portscan")

    if not ctx.live_hosts:
        log.warn("No live hosts -- skipping port scan"); return

    for host in sorted(ctx.live_hosts):
        log.info(f"Scanning {host}...")
        host_dir = make_out_dir(out_dir, host)

        # Nmap scan limited to TCP 22 (SSH) and 3306 (MySQL)
        port_arg = "-p22,3306"

        nmap_xml = os.path.join(host_dir, "nmap_tcp.xml")
        nmap_txt = os.path.join(host_dir, "nmap_tcp.txt")
        rc, out, _ = safe_run(
            f"nmap -{profile['nmap_timing']} -Pn --open {port_arg} {host} "
            f"-oX {nmap_xml} -oN {nmap_txt} --script-timeout 30s",
            timeout=profile["timeout_cmd"]*3, label=f"nmap-tcp-{host}"
        )
        # Parse nmap XML for services
        _parse_nmap_xml(ctx, host, nmap_xml, log)

        log.success(f"  {host}: TCP={ctx.open_ports.get(host,{}).get('tcp',[])} UDP={ctx.open_ports.get(host,{}).get('udp',[])}")

def _parse_nmap_xml(ctx, host, xml_path, log, proto="tcp"):
    try:
        import xml.etree.ElementTree as ET
        if not os.path.exists(xml_path): return
        tree = ET.parse(xml_path)
        root = tree.getroot()
        ports = []
        for port_el in root.findall(f".//port[@protocol='{proto}']"):
            state = port_el.find("state")
            if state is not None and state.get("state") == "open":
                portid = int(port_el.get("portid",0))
                ports.append(portid)
                service_el = port_el.find("service")
                svc_name = service_el.get("name","") if service_el is not None else ""
                svc_version = service_el.get("version","") if service_el is not None else ""
                if svc_name:
                    ctx.service_map.setdefault(host, {})[portid] = {
                        "proto": proto, "service": svc_name, "version": svc_version
                    }
                    log.info(f"    {host}:{portid}/{proto} -> {svc_name} {svc_version}")
        if host not in ctx.open_ports: ctx.open_ports[host] = {}
        existing = ctx.open_ports[host].get(proto, [])
        ctx.open_ports[host][proto] = sorted(set(existing + ports))
    except Exception as e:
        log.debug(f"XML parse error for {host}: {e}")
