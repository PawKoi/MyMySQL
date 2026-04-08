#!/usr/bin/env python3
"""
report/mysql_report.py
Dedicated MySQL HTML report — dark theme, well-spaced, color coded.
"""

import os
import re
from datetime import datetime
from core.logger import get_logger
from core.utils import make_out_dir


def run(ctx):
    log = get_logger()
    log.banner("REPORT -- MySQL Dedicated Report")
    log.set_phase("mysql_report")

    report_dir = make_out_dir(ctx.out_dir, "reports")
    report_path = os.path.join(report_dir, "mysql_report.html")

    # Collect MySQL results from both direct scan and pivot scanner
    mysql_results = {}  # ip_key -> (display_name, dir_path)

    # Direct MySQL scan
    mysql_dir = os.path.join(ctx.out_dir, "services", "mysql")
    if os.path.isdir(mysql_dir):
        for d in os.listdir(mysql_dir):
            full = os.path.join(mysql_dir, d)
            if os.path.isdir(full):
                mysql_results[d] = (d.replace("_", "."), full)

    # Pivot scanner MySQL results
    pivot_dir = os.path.join(ctx.out_dir, "post", "pivot_scanner")
    if os.path.isdir(pivot_dir):
        for pivot_host in os.listdir(pivot_dir):
            pivot_host_dir = os.path.join(pivot_dir, pivot_host)
            if not os.path.isdir(pivot_host_dir):
                continue
            for subdir in os.listdir(pivot_host_dir):
                if subdir.endswith("_mysql"):
                    full = os.path.join(pivot_host_dir, subdir)
                    if os.path.isdir(full):
                        target_ip = subdir.replace("_mysql", "").replace("_", ".")
                        via_ip = pivot_host.replace("_", ".")
                        key = f"{pivot_host}_{subdir}"
                        display = f"{target_ip} (via {via_ip})"
                        mysql_results[key] = (display, full)

    if not mysql_results:
        log.info("No MySQL results found – skipping MySQL report")
        return

    hosts = list(mysql_results.keys())

    mysql_creds = [c for c in ctx.loot.get("credentials", [])
                   if c.get("service") == "mysql"]

    # Deduplicate creds
    seen_creds = set()
    unique_creds = []
    for c in mysql_creds:
        key = f"{c.get('host')}:{c.get('user') or c.get('username')}:{c.get('password')}"
        if key not in seen_creds:
            seen_creds.add(key)
            unique_creds.append(c)

    all_findings = [f for f in (ctx.findings if hasattr(ctx, "findings") else [])
                    if "mysql" in str(f).lower()]

    host_sections = ""
    for key in hosts:
        display_name, host_dir = mysql_results[key]
        files = _read_all_files(host_dir)
        host_sections += _build_host_section(display_name, files)

    creds_html  = _build_creds_table(unique_creds)
    hashes_html = _build_hashes_section_v2(mysql_results)

    total_hosts = len(hosts)
    total_creds = len(unique_creds)
    databases   = _count_databases_v2(mysql_results)
    critical_ct = sum(1 for f in all_findings if "CRITICAL" in str(f).upper())

    dump_section = _build_dump_section(mysql_results)

    # ── Build nav items ──────────────────────────────────────────────────────
    nav_items = [("nav-summary", "&#128200; Summary")]
    if unique_creds:
        nav_items.append(("nav-creds",  "&#128273; Credentials"))
    if hashes_html:
        nav_items.append(("nav-hashes", "&#128272; Hashes"))
    for key in hosts:
        display_name, _ = mysql_results[key]
        safe = _safe_id(display_name)
        nav_items.append((f"nav-host-{safe}", f"&#128421; {display_name}"))
    nav_items.append(("nav-dump", "&#128230; Dumps"))
    nav_items.append(("nav-cmds", "&#128203; Commands"))

    nav_links = "".join(
        f'<a href="#{nid}" class="nav-link">{label}</a>'
        for nid, label in nav_items
    )

    # ── Inject section ids ───────────────────────────────────────────────────
    creds_html_with_id  = creds_html.replace(
        '<div class="section">',
        '<div class="section" id="nav-creds">',
        1) if creds_html else creds_html

    hashes_html_with_id = hashes_html.replace(
        '<div class="section">',
        '<div class="section" id="nav-hashes">',
        1) if hashes_html else hashes_html

    host_sections_with_ids = host_sections
    for key in hosts:
        display_name, _ = mysql_results[key]
        safe = _safe_id(display_name)
        host_sections_with_ids = host_sections_with_ids.replace(
            '<div class="host-card">',
            f'<div class="host-card" id="nav-host-{safe}">',
            1
        )

    # ── CSS ──────────────────────────────────────────────────────────────────
    css = """
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', Arial, sans-serif;
    background: #0d1117;
    color: #e6edf3;
    padding: 30px;
    padding-top: 80px;
    font-size: 15px;
    line-height: 1.6;
    max-width: 1400px;
    margin: 0 auto;
  }
  /* Sticky nav */
  .top-nav {
    position: fixed;
    top: 0; left: 0; right: 0;
    z-index: 1000;
    background: #161b22;
    border-bottom: 2px solid #f0883e;
    padding: 0 24px;
    display: flex;
    align-items: center;
    gap: 4px;
    overflow-x: auto;
    white-space: nowrap;
    height: 52px;
    scrollbar-width: thin;
  }
  .top-nav::-webkit-scrollbar { height: 4px; }
  .top-nav::-webkit-scrollbar-thumb { background: #30363d; border-radius: 2px; }
  .nav-brand {
    color: #f0883e;
    font-weight: bold;
    font-size: 0.9em;
    margin-right: 12px;
    flex-shrink: 0;
    letter-spacing: 0.03em;
  }
  .nav-link {
    color: #8b949e;
    text-decoration: none;
    font-size: 0.82em;
    padding: 6px 12px;
    border-radius: 6px;
    transition: background 0.15s, color 0.15s;
    flex-shrink: 0;
  }
  .nav-link:hover { background: #21262d; color: #e6edf3; }
  .nav-link.active { background: #1f3a5f; color: #58a6ff; }
  /* Scroll offset for fixed nav */
  [id] { scroll-margin-top: 64px; }
  h1 { color: #f0883e; font-size: 2.2em; margin-bottom: 8px; }
  h2 { color: #58a6ff; font-size: 1.3em; margin: 0 0 16px 0;
       border-bottom: 2px solid #30363d; padding-bottom: 8px; }
  h3 { color: #79c0ff; font-size: 1.05em; margin: 16px 0 8px 0; }
  .header {
    background: linear-gradient(135deg, #161b22, #1f2937);
    border: 1px solid #f0883e;
    border-radius: 10px;
    padding: 28px 32px;
    margin-bottom: 28px;
  }
  .meta { color: #8b949e; font-size: 0.95em; margin-top: 10px; line-height: 2; }
  .meta strong { color: #e6edf3; }
  .summary {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 28px;
  }
  .stat {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 20px;
    text-align: center;
  }
  .stat:hover { border-color: #58a6ff; }
  .stat-num { font-size: 2.8em; font-weight: bold; line-height: 1; }
  .stat-label { color: #8b949e; font-size: 0.85em; margin-top: 8px; }
  .red    { color: #f85149; }
  .orange { color: #f0883e; }
  .green  { color: #3fb950; }
  .blue   { color: #58a6ff; }
  .yellow { color: #e3b341; }
  .grey   { color: #8b949e; }
  .section {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 24px;
    margin-bottom: 20px;
  }
  .host-card {
    background: #0d1117;
    border: 1px solid #58a6ff;
    border-radius: 10px;
    padding: 20px 24px;
    margin-bottom: 24px;
  }
  .host-title {
    font-size: 1.25em;
    font-weight: bold;
    color: #58a6ff;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin: 8px 0 16px 0;
    font-size: 0.92em;
  }
  th {
    background: #21262d;
    color: #58a6ff;
    padding: 10px 14px;
    text-align: left;
    border: 1px solid #30363d;
    font-weight: 600;
  }
  td { padding: 9px 14px; border: 1px solid #21262d; vertical-align: top; }
  tr:nth-child(even) { background: #0d1117; }
  tr:hover { background: #1c2128; }
  .badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 12px;
    font-size: 0.75em;
    font-weight: bold;
  }
  .badge-red    { background: #3d1a1a; color: #f85149; border: 1px solid #f85149; }
  .badge-green  { background: #1a3d1a; color: #3fb950; border: 1px solid #3fb950; }
  .badge-blue   { background: #1a2a3d; color: #58a6ff; border: 1px solid #58a6ff; }
  .badge-orange { background: #3d2a1a; color: #f0883e; border: 1px solid #f0883e; }
  /* Collapsible file blocks */
  .file-block {
    margin-bottom: 20px;
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid #30363d;
  }
  .file-label {
    background: #21262d;
    color: #79c0ff;
    padding: 10px 16px;
    font-size: 0.9em;
    font-weight: 600;
    display: flex;
    align-items: center;
    justify-content: space-between;
    cursor: pointer;
    user-select: none;
    transition: background 0.15s;
  }
  .file-label:hover { background: #2d333b; }
  .file-label-left { display: flex; align-items: center; gap: 8px; }
  .file-toggle {
    font-size: 0.8em;
    color: #8b949e;
    transition: transform 0.2s;
    flex-shrink: 0;
  }
  .file-body.collapsed { display: none; }
  .file-toggle.rot { transform: rotate(-90deg); }
  pre {
    background: #0d1117;
    padding: 16px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 0.85em;
    color: #c9d1d9;
    max-height: 500px;
    overflow-y: auto;
    line-height: 1.6;
  }
  pre.critical { border-left: 4px solid #f85149; }
  pre.success  { border-left: 4px solid #3fb950; }
  pre.high     { border-left: 4px solid #f0883e; }
  .hash-row { font-family: 'Consolas', monospace; font-size: 0.82em; }
  .alert {
    border-radius: 8px;
    padding: 14px 18px;
    margin: 10px 0;
    font-size: 0.92em;
    border-left: 4px solid;
  }
  .alert-critical { background: #2d1a1a; border-color: #f85149; color: #ffa198; }
  .alert-info     { background: #1a2a3d; border-color: #58a6ff; color: #79c0ff; }
  .cmd-block { background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
  .cmd-line {
    border-left: 3px solid #58a6ff;
    padding: 8px 12px;
    margin: 6px 0;
    font-family: 'Consolas', monospace;
    font-size: 0.88em;
    color: #8b949e;
    background: #161b22;
    border-radius: 0 4px 4px 0;
  }
  .footer {
    text-align: center;
    color: #484f58;
    font-size: 0.82em;
    margin-top: 32px;
    padding-top: 20px;
    border-top: 1px solid #21262d;
  }
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: #161b22; }
  ::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
"""

    js = """
// Collapsible file blocks
document.querySelectorAll('.file-label').forEach(function(label) {
  label.addEventListener('click', function() {
    var body   = label.nextElementSibling;
    var toggle = label.querySelector('.file-toggle');
    if (!body) return;
    var col = body.classList.toggle('collapsed');
    if (toggle) toggle.classList.toggle('rot', col);
  });
});

// Active nav highlight on scroll
(function() {
  var links   = Array.from(document.querySelectorAll('.nav-link'));
  var targets = links.map(function(l) {
    return document.querySelector(l.getAttribute('href'));
  });
  function onScroll() {
    var scrollY = window.scrollY + 80;
    var active  = null;
    for (var i = 0; i < targets.length; i++) {
      if (targets[i] && targets[i].offsetTop <= scrollY) active = i;
    }
    links.forEach(function(l, i) { l.classList.toggle('active', i === active); });
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
})();

// Smooth scroll with fixed-nav offset
document.querySelectorAll('a[href^="#"]').forEach(function(a) {
  a.addEventListener('click', function(e) {
    var t = document.querySelector(a.getAttribute('href'));
    if (!t) return;
    e.preventDefault();
    window.scrollTo({ top: t.offsetTop - 64, behavior: 'smooth' });
  });
});
"""

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    now_short = datetime.now().strftime("%Y-%m-%d %H:%M")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MySQL Report</title>
<style>{css}</style>
</head>
<body>

<nav class="top-nav">
  <span class="nav-brand">&#128449; MySQL</span>
  {nav_links}
</nav>

<div class="header" id="nav-summary">
  <h1>&#128449; MySQL Penetration Test Report</h1>
  <div class="meta">
    <strong>Target:</strong> {ctx.target} &nbsp;&nbsp;
    <strong>Generated:</strong> {now} &nbsp;&nbsp;
    <strong>Output:</strong> {ctx.out_dir}
  </div>
</div>

<div class="summary">
  <div class="stat">
    <div class="stat-num blue">{total_hosts}</div>
    <div class="stat-label">MySQL Hosts</div>
  </div>
  <div class="stat">
    <div class="stat-num {'red' if total_creds > 0 else 'green'}">{total_creds}</div>
    <div class="stat-label">Credentials Found</div>
  </div>
  <div class="stat">
    <div class="stat-num orange">{databases}</div>
    <div class="stat-label">Databases Exposed</div>
  </div>
  <div class="stat">
    <div class="stat-num {'red' if critical_ct > 0 else 'green'}">{critical_ct}</div>
    <div class="stat-label">Critical Findings</div>
  </div>
</div>

{_build_alerts(all_findings)}
{creds_html_with_id}
{hashes_html_with_id}
{host_sections_with_ids}

<div class="section" id="nav-dump">
  <h2>&#128230; Dumped Database Contents</h2>
  {dump_section}
</div>

<div class="section" id="nav-cmds">
  <h2>&#128203; Reference Commands</h2>
  <div class="cmd-block">
    <div class="cmd-line">nmap -T3 -p3306 --script mysql-info,mysql-empty-password,mysql-databases,mysql-users,mysql-variables &lt;target&gt;</div>
    <div class="cmd-line">hydra -L usernames.txt -P passwords.txt -s 3306 &lt;target&gt; mysql</div>
    <div class="cmd-line">mysql -h &lt;target&gt; -P 3306 -u root -p&lt;pass&gt; --connect-timeout=15 -e "SHOW DATABASES;"</div>
    <div class="cmd-line">mysql -h &lt;target&gt; -P 3306 -u root -p&lt;pass&gt; -e "SELECT host,user,authentication_string FROM mysql.user;"</div>
    <div class="cmd-line">mysql -h &lt;target&gt; -P 3306 -u root -p&lt;pass&gt; -e "SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema NOT IN ('information_schema','performance_schema','sys','mysql');"</div>
    <div class="cmd-line">mysql -h &lt;target&gt; -P 3306 -u root -p&lt;pass&gt; -e "SELECT LOAD_FILE('/etc/passwd');"</div>
    <div class="cmd-line">mysql -h &lt;target&gt; -P 3306 -u root -p&lt;pass&gt; -e "SHOW VARIABLES LIKE 'plugin_dir';"</div>
  </div>
</div>

<div class="footer">
  AutoPwn MySQL Report &nbsp;&#183;&nbsp; {now_short} &nbsp;&#183;&nbsp; Authorised use only
</div>

<script>{js}</script>
</body>
</html>"""

    try:
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html)
        log.success(f"MySQL HTML report -> {report_path}")
    except Exception as e:
        log.error(f"MySQL report write failed: {e}")

    # Per-host individual reports
    for key in hosts:
        display_name, host_dir = mysql_results[key]
        single_files      = _read_all_files(host_dir)
        single_section    = _build_host_section(display_name, single_files)
        single_dump       = _build_dump_section({key: (display_name, host_dir)})
        single_creds      = [c for c in unique_creds if display_name.split(" ")[0] in c.get("host","")]
        single_creds_html = _build_creds_table(single_creds)
        single_hashes     = _build_hashes_section_v2({key: (display_name, host_dir)})
        safe_name = display_name.replace(" ","_").replace("/","_").replace("(","").replace(")","").replace(".","_")
        host_report_path = os.path.join(report_dir, f"mysql_{safe_name}.html")
        single_html = html.replace(creds_html_with_id, single_creds_html).replace(
            hashes_html_with_id, single_hashes).replace(
            host_sections_with_ids, single_section).replace(
            dump_section, single_dump).replace(
            "&#128449; MySQL Penetration Test Report",
            f"&#128449; MySQL Report: {display_name}"
        )
        try:
            with open(host_report_path, "w", encoding="utf-8") as f:
                f.write(single_html)
            log.success(f"MySQL host report -> {host_report_path}")
        except Exception as e:
            log.error(f"Host report failed [{display_name}]: {e}")


# ── Helpers ──────────────────────────────────────────────────────────────────

def _safe_id(text):
    return re.sub(r"[^a-zA-Z0-9_-]", "_", text)


def _read_all_files(host_dir):
    files = {}
    try:
        for fname in sorted(os.listdir(host_dir)):
            fpath = os.path.join(host_dir, fname)
            if os.path.isfile(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read().strip()
                    if content:
                        files[fname] = content
                except Exception:
                    pass
    except Exception:
        pass
    return files


def _build_alerts(findings):
    alerts = ""
    for f in findings:
        s = str(f).upper()
        if "FILE PRIVILEGE" in s or "LFI" in s:
            alerts += '<div class="alert alert-critical">&#9888; <strong>CRITICAL:</strong> MySQL root has FILE privilege — local file read/write possible</div>'
        if "EMPTY PASSWORD" in s:
            alerts += '<div class="alert alert-critical">&#9888; <strong>CRITICAL:</strong> MySQL root may have empty password</div>'
    return f'<div style="margin-bottom:20px">{alerts}</div>' if alerts else ""


def _build_creds_table(creds):
    if not creds:
        return ""
    rows = ""
    for c in creds:
        user = c.get("user") or c.get("username", "")
        pwd  = c.get("password", "")
        rows += f"""<tr>
            <td>{c.get('host','')}</td>
            <td>{c.get('port', 3306)}</td>
            <td class="green" style="font-weight:bold">{user}</td>
            <td class="red" style="font-weight:bold;font-family:monospace">{_escape(pwd)}</td>
            <td class="grey">{c.get('source','brute')}</td>
        </tr>"""
    return f"""
    <div class="section">
        <h2>&#128273; Credentials Found</h2>
        <table>
            <tr><th>Host</th><th>Port</th><th>Username</th><th>Password</th><th>Source</th></tr>
            {rows}
        </table>
    </div>"""


def _build_hashes_section(hosts, mysql_dir):
    hashes = []
    hash_pattern = re.compile(r"(\w[\w.%@-]*)\s+(\$[A-Za-z0-9$./]+)\s+([\w.%@:-]+)")
    for host in hosts:
        for fname in ["mysql_exploit.txt", "nmap_mysql.txt"]:
            fpath = os.path.join(mysql_dir, host, fname)
            try:
                content = open(fpath, encoding="utf-8", errors="replace").read()
                for m in hash_pattern.finditer(content):
                    hashes.append({
                        "host": host, "user": m.group(1),
                        "hash": m.group(2), "from_host": m.group(3),
                    })
            except Exception:
                pass
    if not hashes:
        return ""
    rows = ""
    seen = set()
    for h in hashes:
        key = f"{h['user']}:{h['hash'][:20]}"
        if key in seen:
            continue
        seen.add(key)
        rows += f"""<tr>
            <td>{h['host']}</td>
            <td class="green">{h['user']}</td>
            <td class="grey">{h['from_host']}</td>
            <td class="hash-row yellow">{_escape(h['hash'])}</td>
        </tr>"""
    return f"""
    <div class="section">
        <h2>&#128272; Password Hashes (for offline cracking)</h2>
        <div class="alert alert-info">
            Crack with: <strong>john --wordlist=rockyou.txt hashes.txt</strong> or
            <strong>hashcat -m 7401 hashes.txt rockyou.txt</strong>
        </div>
        <table>
            <tr><th>Host</th><th>User</th><th>Accessible From</th><th>Hash</th></tr>
            {rows}
        </table>
    </div>"""


def _build_host_section(host, files):
    if not files:
        return f'<div class="host-card"><div class="host-title">&#128421; {host}:3306 <span class="badge badge-blue">NO OUTPUT</span></div></div>'

    version = ""
    for fname, content in files.items():
        m = re.search(r"Version:\s*([\d.]+[-\w]*)", content)
        if m: version = m.group(1); break
        m2 = re.search(r"mysql\s+([\d.]+[-\w.]+)", content, re.IGNORECASE)
        if m2: version = m2.group(1); break

    badges = ""
    all_content = " ".join(files.values())
    if re.search(r"login:|valid pair|MySQL cred", all_content):
        badges += '<span class="badge badge-red">CREDS FOUND</span>'
    if "FILE" in all_content and "privilege" in all_content.lower():
        badges += '<span class="badge badge-orange">FILE PRIV</span>'
    if "kitchenday" in all_content or "kitchenstuff" in all_content:
        badges += '<span class="badge badge-green">DBs EXPOSED</span>'

    version_str = f" <span class='grey' style='font-size:0.85em'>MySQL {version}</span>" if version else ""

    file_order = [
        ("nmap_mysql.txt",    "&#128225;", "nmap MySQL Scripts"),
        ("mysql_exploit.txt", "&#128165;", "Full Recon Output (Users, Databases, Tables, Hashes)"),
        ("mysql_udf.txt",     "&#128295;", "UDF / Plugin Directory Check"),
        ("mysql_lateral.txt", "&#8596;",   "Lateral Movement — Remote Users"),
        ("hydra_mysql.txt",   "&#128273;", "Hydra Brute Force Results"),
        ("msf_mysql_all.txt", "&#127919;", "Metasploit Module Output"),
    ]

    file_blocks = ""
    shown = set()

    for fname, icon, label in file_order:
        if fname not in files:
            continue
        shown.add(fname)
        content = files[fname]
        css = ""
        if "FILE" in content and "privilege" in content.lower():
            css = "critical"
        elif "login: root" in content or "valid pair" in content.lower():
            css = "success"
        elif content.startswith("ERROR"):
            css = "high"

        extra = ""
        if fname == "mysql_exploit.txt":
            dbs = list(set(re.findall(
                r"^(kitchenday|kitchenstuff|[a-zA-Z][a-zA-Z0-9_]{2,})$",
                content, re.MULTILINE)))
            skip = {"information_schema","performance_schema","sys","mysql",
                    "Database","Variable_name","Value","TABLE_SCHEMA","TABLE_NAME",
                    "NULL","VERSION","USER","hostname","datadir","host","user"}
            dbs = [d for d in dbs if d not in skip]
            if dbs:
                db_badges = " ".join(
                    f'<span class="badge badge-green">{d}</span>' for d in sorted(set(dbs)))
                extra = f'<div style="padding:10px 16px;background:#0d1117;border-bottom:1px solid #30363d">Databases: {db_badges}</div>'

        file_blocks += f"""
        <div class="file-block">
            <div class="file-label">
                <span class="file-label-left">{icon} {label} &nbsp;<span class="grey">— {fname}</span></span>
                <span class="file-toggle">&#9660;</span>
            </div>
            <div class="file-body">
                {extra}
                <pre class="{css}">{_escape(content)}</pre>
            </div>
        </div>"""

    for fname, content in files.items():
        if fname not in shown:
            file_blocks += f"""
            <div class="file-block">
                <div class="file-label">
                    <span class="file-label-left">&#128196; {fname}</span>
                    <span class="file-toggle">&#9660;</span>
                </div>
                <div class="file-body">
                    <pre>{_escape(content)}</pre>
                </div>
            </div>"""

    return f"""
    <div class="host-card">
        <div class="host-title">&#128421; {host}:3306{version_str} &nbsp; {badges}</div>
        {file_blocks}
    </div>"""


def _count_databases(mysql_dir, hosts):
    found = set()
    skip = {"information_schema","performance_schema","sys","mysql",
            "Database","Variable_name","Value","NULL","VERSION"}
    for host in hosts:
        host_dir = os.path.join(mysql_dir, host)
        for fname in os.listdir(host_dir):
            fpath = os.path.join(host_dir, fname)
            try:
                content = open(fpath, encoding="utf-8", errors="replace").read()
                for line in content.splitlines():
                    line = line.strip().strip("|").strip()
                    if (line and line not in skip and
                            re.match(r"^[a-zA-Z][a-zA-Z0-9_]{2,}$", line)):
                        found.add(line)
            except Exception:
                pass
    return len(found)


def _build_dump_section(mysql_results):
    html = ""
    for key, (display, host_dir) in mysql_results.items():
        dump_dir = os.path.join(host_dir, "dump", "databases")
        if not os.path.isdir(dump_dir):
            dump_dir = os.path.join(host_dir, "databases")
        if not os.path.isdir(dump_dir):
            continue
        for db_name in sorted(os.listdir(dump_dir)):
            db_dir = os.path.join(dump_dir, db_name)
            if not os.path.isdir(db_dir):
                continue
            tables_dir = os.path.join(db_dir, "tables")
            table_sections = ""
            if os.path.isdir(tables_dir):
                table_files = {}
                for fname in sorted(os.listdir(tables_dir)):
                    fpath = os.path.join(tables_dir, fname)
                    if not os.path.isfile(fpath):
                        continue
                    if fname.endswith("_data.txt"):
                        tname = fname[:-9]
                        kind  = "data"
                    elif fname.endswith("_count.txt"):
                        tname = fname[:-10]
                        kind  = "count"
                    else:
                        continue
                    table_files.setdefault(tname, {})[kind] = fpath

                for tname, tfiles in sorted(table_files.items()):
                    count_str = ""
                    if "count" in tfiles:
                        try:
                            count_str = open(tfiles["count"]).read().strip().splitlines()[-1]
                        except: pass

                    table_html = ""
                    if "data" in tfiles:
                        try:
                            raw   = open(tfiles["data"], encoding="utf-8", errors="replace").read().strip()
                            lines = [l for l in raw.splitlines() if l.strip()]
                            if len(lines) >= 2:
                                headers = lines[0].split("\t")
                                th_row  = "".join(f"<th>{_escape(h)}</th>" for h in headers)
                                td_rows = ""
                                for line in lines[1:]:
                                    cols = line.split("\t")
                                    cells = ""
                                    for i, h in enumerate(headers):
                                        val = cols[i] if i < len(cols) else ""
                                        hl  = h.lower()
                                        if hl in ("password","password_hash","pwd","secret","token","hash"):
                                            css = "red"
                                        elif hl in ("salary","paycheck"):
                                            css = "green"
                                        else:
                                            css = ""
                                        cells += f'<td class="{css}">{_escape(val)}</td>'
                                    td_rows += f"<tr>{cells}</tr>"
                                table_html = f'''<div style="overflow-x:auto;margin-top:10px">
                                <table><tr>{th_row}</tr>{td_rows}</table></div>'''
                            else:
                                table_html = f"<pre>{_escape(raw)}</pre>"
                        except Exception as e:
                            table_html = f"<pre>Error: {e}</pre>"

                    sens_badge = ""
                    if any(x in tname.lower() for x in ("admin","employee","user","password")):
                        sens_badge = '<span class="badge badge-red">SENSITIVE</span>'

                    table_sections += f'''
                    <div style="margin-bottom:28px">
                        <h3 style="display:flex;align-items:center;gap:10px;font-size:1.1em;margin-bottom:10px">
                            &#128196; {tname} {sens_badge}
                            <span class="badge badge-blue">{count_str} rows</span>
                        </h3>
                        {table_html}
                    </div>'''

            sens_html = ""
            sens_file = os.path.join(db_dir, "sensitive_cols.txt")
            if os.path.isfile(sens_file):
                try:
                    raw = open(sens_file, encoding="utf-8", errors="replace").read().strip()
                    if raw:
                        sens_html = f'''<div class="alert alert-critical" style="margin-bottom:16px">
                            &#9888; <strong>Sensitive Columns Detected:</strong><br>
                            <pre style="background:transparent;padding:8px 0;color:#ffa198">{_escape(raw)}</pre>
                        </div>'''
                except: pass

            sql_note = ""
            sql_file = os.path.join(db_dir, f"{db_name}_full.sql")
            if os.path.isfile(sql_file):
                size = os.path.getsize(sql_file)
                sql_note = f'''<div class="alert alert-info" style="margin-bottom:16px">
                    &#128190; Full SQL dump: <strong>{sql_file}</strong> ({size:,} bytes)
                </div>'''

            html += f'''
            <div class="host-card" style="border-color:#f0883e;margin-bottom:32px">
                <div class="host-title" style="color:#f0883e;font-size:1.4em">
                    &#128449; Database: <strong>{db_name}</strong>
                    &nbsp;<span class="grey" style="font-size:0.75em">on {display}</span>
                </div>
                {sql_note}
                {sens_html}
                <h3 style="margin-bottom:16px">&#128218; Table Data</h3>
                {table_sections if table_sections else '<div class="alert alert-info">No table data captured</div>'}
            </div>'''
    return html if html else '<div class="alert alert-info">No database dumps found</div>'


def _escape(text):
    return (text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _build_hashes_section_v2(mysql_results):
    hashes = []
    hash_pattern = re.compile(r"([\w.%@-]+)\s+(\*[A-F0-9]{40}|\$[A-Za-z0-9$./]+)\s*([\w.%@:-]*)")
    for key, (display, host_dir) in mysql_results.items():
        for fname in os.listdir(host_dir):
            fpath = os.path.join(host_dir, fname)
            try:
                content2 = open(fpath, encoding="utf-8", errors="replace").read()
                for m in hash_pattern.finditer(content2):
                    hashes.append({
                        "host": display,
                        "user": m.group(1),
                        "hash": m.group(2),
                        "from_host": m.group(3),
                    })
            except Exception:
                pass
    if not hashes:
        return ""
    rows = ""
    seen = set()
    for h in hashes:
        key2 = f"{h['user']}:{h['hash'][:20]}"
        if key2 in seen:
            continue
        seen.add(key2)
        rows += f"""<tr>
            <td>{h['host']}</td>
            <td class="green">{h['user']}</td>
            <td class="grey">{h['from_host']}</td>
            <td class="hash-row yellow">{_escape(h['hash'])}</td>
        </tr>"""
    if not rows:
        return ""
    return f"""
    <div class="section">
        <h2>&#128272; Password Hashes (for offline cracking)</h2>
        <div class="alert alert-info">
            Crack with: <strong>john --wordlist=rockyou.txt hashes.txt</strong> or
            <strong>hashcat -m 7401 hashes.txt rockyou.txt</strong>
        </div>
        <table>
            <tr><th>Host</th><th>User</th><th>Accessible From</th><th>Hash</th></tr>
            {rows}
        </table>
    </div>"""


def _count_databases_v2(mysql_results):
    found = set()
    skip = {"information_schema","performance_schema","sys","mysql",
            "Database","Variable_name","Value","NULL","VERSION"}
    for key, (display, host_dir) in mysql_results.items():
        try:
            for fname in os.listdir(host_dir):
                fpath = os.path.join(host_dir, fname)
                try:
                    content2 = open(fpath, encoding="utf-8", errors="replace").read()
                    for line in content2.splitlines():
                        line = line.strip()
                        if (line and line not in skip and
                                re.match(r"^[a-zA-Z][a-zA-Z0-9_]{2,}$", line)):
                            found.add(line)
                except Exception:
                    pass
        except Exception:
            pass
    return len(found)
