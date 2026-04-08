import shutil, os, tempfile

OUTPUT_DIR    = os.environ.get("AUTOPWN_OUT", "/tmp/autopwn_results")
SPEED_PROFILE = os.environ.get("AUTOPWN_SPEED", "fast")

PROFILES = {
    "fast":     {"nmap_timing":"T4","timeout_cmd":60, "threads":10,"hydra_tasks":4, "masscan_rate":10000,"brute_enabled":False},
    "balanced": {"nmap_timing":"T3","timeout_cmd":180,"threads":20,"hydra_tasks":8, "masscan_rate":5000, "brute_enabled":True},
    "deep":     {"nmap_timing":"T2","timeout_cmd":600,"threads":30,"hydra_tasks":16,"masscan_rate":2000, "brute_enabled":True},
}
def get_profile(): return PROFILES.get(SPEED_PROFILE, PROFILES["fast"])

_TOOL_CACHE = {}
def tool_available(name):
    if name not in _TOOL_CACHE:
        path = shutil.which(name)
        if not path and name == "impacket-mssqlclient":
            for alt in ["/usr/bin/impacket-mssqlclient",
                        "/usr/local/bin/impacket-mssqlclient",
                        "/usr/share/doc/python3-impacket/examples/mssqlclient.py"]:
                if os.path.isfile(alt): path = alt; break
        if not path and name == "crackmapexec":
            path = shutil.which("cme") or shutil.which("crackmapexec")
        _TOOL_CACHE[name] = path
    return bool(_TOOL_CACHE[name])

def get_tool_path(name):
    tool_available(name)
    return _TOOL_CACHE.get(name)

SERVICE_PORTS = {
    "ftp":[21],"ssh":[22],"telnet":[23],"smtp":[25,465,587],"dns":[53],
    "http":[80,8080,8000,8888,8008],"kerberos":[88],"pop3":[110,995],
    "rpc":[111,135],"imap":[143,993],"snmp":[161,162],
    "ldap":[389,636,3268,3269],"smb":[445,139],"mssql":[1433,1434],
    "https":[443,8443],"nfs":[2049],"mysql":[3306],"postgres":[5432],
    "rdp":[3389],"vnc":[5900,5901],"winrm":[5985,5986],
    "redis":[6379],"openvpn":[1194],"ike":[500,4500],
}

FALLBACK_PASSWORDS = [
    "","password","Password1","password123","P@ssw0rd","admin","admin123",
    "letmein","welcome","qwerty","12345678","sa","root","toor","test",
    "guest","changeme","pass","1234","administrator","Admin@123",
    "Passw0rd","Password@1","Summer2023!","Winter2023!","Aa123456!",
]
FALLBACK_USERS = [
    "admin","administrator","root","sa","user","guest","test",
    "service","backup","sysadmin","manager","operator","support",
]

WORDLIST_PASSWORDS = [
    "/home/ubuntu_user/ris602/wordlists/passwords.txt",
]
WORDLIST_USERNAMES = [
    "/home/ubuntu_user/ris602/wordlists/usernames.txt",
]
WORDLIST_DIRS = [
    "/home/ubuntu_user/ris602/wordlists/dirs.txt",
]
WORDLIST_VHOSTS = [
    "/snap/seclists/1214/Discovery/DNS/subdomains-top1million-5000.txt",
]

def _fallback(paths, fallback, suffix):
    for p in paths:
        if os.path.isfile(p): return p
    tmp = os.path.join(tempfile.gettempdir(), f"autopwn_fb_{suffix}.txt")
    with open(tmp,"w") as f: f.write("\n".join(fallback))
    return tmp

def get_password_wordlist(): return _fallback(WORDLIST_PASSWORDS, FALLBACK_PASSWORDS, "pass")
def get_user_wordlist():     return _fallback(WORDLIST_USERNAMES, FALLBACK_USERS, "user")
def get_dir_wordlist():      return _fallback(WORDLIST_DIRS, ["admin","login","api","backup","config","upload","test","dev"], "dir")

MSF_MSSQL_MODULES = [
    "auxiliary/scanner/mssql/mssql_ping","auxiliary/scanner/mssql/mssql_login",
    "auxiliary/admin/mssql/mssql_enum","auxiliary/admin/mssql/mssql_exec",
]
MSF_SMB_MODULES = [
    "auxiliary/scanner/smb/smb_ms17_010","auxiliary/scanner/smb/smb_version",
    "auxiliary/scanner/smb/smb_enumshares","auxiliary/scanner/smb/smb_enumusers",
]
MSF_RDP_MODULES = [
    "auxiliary/scanner/rdp/rdp_scanner",
    "auxiliary/scanner/rdp/cve_2019_0708_bluekeep",
]
SNMP_COMMUNITIES  = ["public","private","community","manager","admin","snmpd","cisco","monitor",""]
USER_AGENTS       = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
]
EVASION_DEFAULTS  = {"fragment":False,"decoys":False,"source_port":None,"timing":"T4","mtu":None}
