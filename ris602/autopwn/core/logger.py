import os, sys, threading
from datetime import datetime

class C:
    RESET="\033[0m";BOLD="\033[1m";RED="\033[91m";GREEN="\033[92m"
    YELLOW="\033[93m";BLUE="\033[94m";CYAN="\033[96m";WHITE="\033[97m"
    GREY="\033[90m";MAGENTA="\033[95m"

_lock = threading.Lock()

class AutopwnLogger:
    def __init__(self, out_dir):
        self.out_dir = out_dir
        os.makedirs(out_dir, exist_ok=True)
        self.log_path = os.path.join(out_dir, "autopwn_full.log")
        self._file = open(self.log_path, "a", buffering=1)
        self._phase = "INIT"

    def set_phase(self, phase):
        self._phase = phase
        self._write_file(f"\n{'='*70}\nPHASE: {phase}\n{'='*70}")

    def _write_file(self, msg):
        try:
            ts = datetime.now().strftime("%H:%M:%S")
            self._file.write(f"[{ts}] {msg}\n")
        except: pass

    def _print(self, prefix, colour, msg):
        ts = datetime.now().strftime("%H:%M:%S")
        with _lock:
            # \033[2K clears the current line (progress bar), then print log line
            sys.stdout.write(f"\033[2K\r{colour}{C.BOLD}[{prefix}]{C.RESET} {C.GREY}{ts}{C.RESET} {msg}\n")
            sys.stdout.flush()
        self._write_file(f"[{prefix}] {msg}")

    def info(self, msg):    self._print("*", C.CYAN,    msg)
    def success(self, msg): self._print("+", C.GREEN,   msg)
    def warn(self, msg):    self._print("!", C.YELLOW,  msg)
    def error(self, msg):   self._print("-", C.RED,     msg)
    def debug(self, msg):   self._print("~", C.GREY,    msg)

    def banner(self, msg):
        line = "=" * 62
        with _lock:
            sys.stdout.write(f"\033[2K\r\n{C.BLUE}{C.BOLD}{line}\n  {msg}\n{line}{C.RESET}\n\n")
            sys.stdout.flush()
        self._write_file(f"[BANNER] {msg}")

    def finding(self, severity, host, msg):
        cols = {"CRITICAL":C.RED,"HIGH":C.RED,"MEDIUM":C.YELLOW,"LOW":C.CYAN,"INFO":C.WHITE}
        col = cols.get(severity.upper(), C.WHITE)
        with _lock:
            sys.stdout.write(f"\033[2K\r{col}{C.BOLD}[{severity.upper()}]{C.RESET} {C.MAGENTA}{host}{C.RESET} -> {msg}\n")
            sys.stdout.flush()
        self._write_file(f"[FINDING:{severity}] {host} -> {msg}")

    def raw(self, data): self._write_file(data)

    def close(self):
        try: self._file.close()
        except: pass

_logger = None

def init_logger(out_dir):
    global _logger
    _logger = AutopwnLogger(out_dir)
    return _logger

def get_logger():
    global _logger
    if _logger is None:
        _logger = AutopwnLogger("/tmp/autopwn_results")
    return _logger
