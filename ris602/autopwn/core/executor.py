import subprocess, threading, os, signal, shlex
from typing import Tuple
from core.logger import get_logger

def safe_run(cmd, timeout=60, shell=False, input_data=None, env=None, cwd=None, capture=True, label=""):
    log = get_logger()
    if isinstance(cmd, str) and not shell:
        try:    cmd_list = shlex.split(cmd)
        except: cmd_list = cmd.split()
    else: cmd_list = cmd
    display = cmd if isinstance(cmd, str) else " ".join(str(x) for x in cmd_list)
    log.debug(f"RUN{' ['+label+']' if label else ''}: {display[:120]}")
    try:
        proc = subprocess.Popen(
            cmd_list if not shell else cmd,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.PIPE if capture else None,
            stdin=subprocess.PIPE if input_data else None,
            shell=shell,
            env={**os.environ, **(env or {})},
            cwd=cwd,
            preexec_fn=os.setsid,
        )
        try:
            stdout, stderr = proc.communicate(
                input=input_data.encode() if input_data else None,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            try: os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except: proc.kill()
            proc.communicate()
            log.warn(f"TIMEOUT ({timeout}s){' ['+label+']' if label else ''}: {display[:80]}")
            return (-1, "", f"TIMEOUT after {timeout}s")
        out = stdout.decode(errors="replace") if stdout else ""
        err = stderr.decode(errors="replace") if stderr else ""
        if proc.returncode != 0:
            log.debug(f"Exit {proc.returncode}{' ['+label+']' if label else ''}: {display[:80]}")
        return (proc.returncode, out, err)
    except FileNotFoundError:
        tool = cmd_list[0] if isinstance(cmd_list, list) else display.split()[0]
        log.warn(f"Tool not found: {tool} -- skipping")
        return (-2, "", f"Tool not found: {tool}")
    except PermissionError as e:
        log.error(f"Permission denied: {display[:60]} -- {e}")
        return (-3, "", str(e))
    except Exception as e:
        log.error(f"Unexpected error [{label or display[:60]}]: {e}")
        return (-4, "", str(e))

def run_to_file(cmd, out_path, timeout=120, shell=False, label=""):
    rc, out, err = safe_run(cmd, timeout=timeout, shell=shell, label=label)
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w") as f:
        f.write(out)
        if err: f.write(f"\n--- STDERR ---\n{err}")
    return rc, out_path

def run_msf_resource(resource_path, timeout=300):
    from config import tool_available
    log = get_logger()
    if not tool_available("msfconsole"):
        log.warn("msfconsole not found -- skipping MSF")
        return (-2, "", "msfconsole not found")
    return safe_run(["msfconsole","-q","-r",resource_path], timeout=timeout, label="msfconsole", input_data="n\n")

def write_msf_resource(path, lines):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

def run_parallel(tasks, max_workers=10):
    import threading
    results = [None] * len(tasks)
    threads = []
    sem = threading.Semaphore(max_workers)
    def worker(idx, fn, args, kwargs):
        with sem:
            try: results[idx] = fn(*args, **kwargs)
            except Exception as e:
                get_logger().error(f"Parallel task {idx} failed: {e}")
                results[idx] = None
    for i, (fn, args, kwargs) in enumerate(tasks):
        t = threading.Thread(target=worker, args=(i, fn, args, kwargs), daemon=True)
        threads.append(t); t.start()
    for t in threads: t.join()
    return results
