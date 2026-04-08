import ipaddress, os, re, json, socket
from typing import List

def expand_cidr(target):
    target = target.strip()
    m = re.match(r"^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$", target)
    if m:
        base, s, e = m.group(1), int(m.group(2)), int(m.group(3))
        return [f"{base}{i}" for i in range(s, e+1)]
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses == 1: return [str(net.network_address)]
        return [str(h) for h in net.hosts()]
    except ValueError:
        try: return [socket.gethostbyname(target)]
        except: return [target]

def is_valid_ip(ip):
    try: ipaddress.ip_address(ip); return True
    except: return False

def port_list_from_string(ports_str):
    result = []
    for part in ports_str.split(","):
        part = part.strip()
        if "-" in part:
            try:
                lo, hi = part.split("-",1)
                result.extend(range(int(lo), int(hi)+1))
            except: pass
        else:
            try: result.append(int(part))
            except: pass
    return sorted(set(result))

def make_out_dir(base, *sub):
    path = os.path.join(base, *sub)
    os.makedirs(path, exist_ok=True)
    return path

def save_json(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path,"w") as f: json.dump(data, f, indent=2, default=str)

def load_json(path):
    try:
        with open(path) as f: return json.load(f)
    except: return None

def append_file(path, line):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path,"a") as f: f.write(line.rstrip("\n")+"\n")

def read_file(path):
    try:
        with open(path, errors="replace") as f: return f.read()
    except: return ""

def grep_file(path, pattern):
    results = []
    try:
        with open(path, errors="replace") as f:
            for line in f:
                if re.search(pattern, line, re.IGNORECASE): results.append(line.rstrip())
    except: pass
    return results

def extract_ips(text):
    pattern = r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    found = re.findall(pattern, text)
    valid = []
    for ip in found:
        try:
            obj = ipaddress.ip_address(ip)
            if not obj.is_loopback and not obj.is_link_local:
                valid.append(ip)
        except: pass
    return list(dict.fromkeys(valid))

def extract_credentials(text):
    """Parse tool output for username:password pairs."""
    creds = []; seen = set()
    patterns = [
        # Hydra:  [22][ssh] host: 1.2.3.4  login: admin  password: pass
        r"\[\d+\]\[[\w-]+\]\s+host:\s*\S+\s+login:\s*(\S+)\s+password:\s*(\S+)",
        # Generic SUCCESS
        r"(?i)\[(?:SUCCESS|\+)\].*?login[:\s]+(\S+).*?password[:\s]+(\S+)",
        # CME [+] 1.2.3.4  DOMAIN\user:pass
        r"\[\+\]\s+\S+\s+\S*\\?(\w[\w.-]+):(\S+)",
        # impacket Authenticated
        r"(?i)Authenticated\s+as\s+(\S+).*?password[:\s]+(\S+)",
        # user:pass is valid
        r"(?i)(\S+):(\S+)\s+(?:is valid|logged in|authenticated successfully)",
    ]
    for pat in patterns:
        for m in re.finditer(pat, text):
            try:
                u, p = m.group(1).strip(), m.group(2).strip()
                key = f"{u}:{p}"
                if key not in seen and u and 1 < len(u) < 64 and len(p) < 128:
                    seen.add(key)
                    creds.append({"user": u, "password": p, "raw": m.group(0)[:120]})
            except: pass
    return creds

def extract_hashes(text):
    patterns = [
        r"[a-fA-F0-9]{32}:[a-fA-F0-9]{32}",    # LM:NTLM
        r"\$NETNTLMv2\$[^\s:]{10,}",
        r"\$krb5tgs\$[^\s]{20,}",
        r"\$krb5asrep\$[^\s]{20,}",
    ]
    found = []
    for pat in patterns: found.extend(re.findall(pat, text))
    return list(dict.fromkeys(found))

def port_is_open(host, port, timeout=1.5):
    try:
        s = socket.socket(); s.settimeout(timeout)
        r = s.connect_ex((host,port)); s.close()
        return r == 0
    except: return False

def grab_banner(host, port, timeout=3.0, send=b"\r\n"):
    s = None
    try:
        s = socket.socket(); s.settimeout(timeout)
        s.connect((host,port)); s.sendall(send)
        data = s.recv(2048)
        return data.decode(errors="replace").strip()
    except: return ""
    finally:
        if s:
            try: s.close()
            except: pass

def sanitize_hostname(h):
    return re.sub(r"[^a-zA-Z0-9._-]","_",h)
