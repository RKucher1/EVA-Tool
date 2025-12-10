#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  Author :  Ryan Kucher
#  Version:  8.7
#  Date   :  2025-12-10
# ─────────────────────────────────────────────────────────────
"""
EVA Scanner v8.7 — Sequential, banner-style network scanner with live output.

Highlights
----------
• Human-friendly errors and guidance (no log files, no stack traces by default).
• Live, colorized streaming of command output with clear section headers.
• Fast-path TLS: if the port number contains "443" anywhere (e.g., 443, 1443, 4433, 10443),
  run testssl immediately and skip nmap for speed.
• Smarter TLS trigger in generic flow (uses THIS port's service line only; skips reverse-ssl, IKE).
• Web visibility helper: if site is reachable, displays URLs in a summary section
  at the end of the scan (no auto-opening Firefox windows). robots.txt contents are
  also printed inline when found.
• SNMP: still runs even if netcat reports closed; nmap SNMP + snmp-check (public/private).
• IKE: only port 500 runs the ike-scan trilogy; port 4500 stays generic.
• testssl has a 10 minute (600s) timeout with watchdog timer that kills hung processes
  even when they produce no output (robust timeout enforcement).
• Animated spinners with elapsed time for each IP being scanned in interactive mode.

Requirements (Kali/Debian)
--------------------------
sudo apt-get install nmap netcat-traditional curl dnsutils snmpcheck ssh-audit ike-scan
pip install colorama tqdm requests
(Optional) testssl.sh: place at /root/tools/testssl.sh/testssl.sh or install 'testssl' CLI.
"""

# ───────── stdlib
import argparse
import logging
import os
import re
import signal
import socket
import subprocess
import sys
import time
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from http import HTTPStatus
from io import StringIO
from threading import Lock

# ───────── 3rd-party
import requests
import urllib3
from colorama import Fore, Style, init
from tqdm import tqdm

# ───────── init
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ───────── ANSI escape codes for terminal control
CURSOR_UP = "\033[A"
CURSOR_DOWN = "\033[B"
CLEAR_LINE = "\033[2K"
CURSOR_START = "\r"
HIDE_CURSOR = "\033[?25l"
SHOW_CURSOR = "\033[?25h"

def move_cursor_up(n: int) -> str:
    """Return ANSI escape code to move cursor up n lines."""
    return f"\033[{n}A" if n > 0 else ""

def clear_lines(n: int):
    """Clear n lines above current cursor position."""
    for _ in range(n):
        print(CURSOR_UP + CLEAR_LINE, end="")


# ───────── Thread-local output capture for concurrent scans
_thread_local = threading.local()

def is_capturing():
    """Check if current thread is in output capture mode."""
    return getattr(_thread_local, 'capturing', False)

def get_capture_buffer():
    """Get the capture buffer for current thread."""
    return getattr(_thread_local, 'buffer', None)

def start_capture():
    """Start capturing output for current thread."""
    _thread_local.capturing = True
    _thread_local.buffer = []

def stop_capture():
    """Stop capturing and return captured output."""
    _thread_local.capturing = False
    buffer = getattr(_thread_local, 'buffer', [])
    _thread_local.buffer = []
    return "\n".join(buffer)

def write_output(text, end="\n"):
    """Write text to stdout or capture buffer depending on mode."""
    if is_capturing():
        buffer = get_capture_buffer()
        if buffer is not None:
            buffer.append(text + (end if end != "\n" else ""))
    else:
        print(text, end=end)


class ProgressTracker:
    """
    Thread-safe progress tracker that displays scan progress in-place.
    Uses ANSI escape codes to update a fixed area of the terminal.
    Includes animated spinners for active scans.
    """
    # Braille spinner frames for smooth animation
    SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

    def __init__(self, total_targets: int, lock: Lock):
        self.total_targets = total_targets
        self.lock = lock
        self.progress = {}  # target_id -> (ip, current_port, port_idx, total_ports, status, start_time)
        self.lines_printed = 0
        self._initialized = False
        self._spinner_idx = 0
        self._spinner_thread = None
        self._stop_spinner = threading.Event()
        self._start_spinner_thread()

    def _start_spinner_thread(self):
        """Start background thread to animate spinners."""
        def spinner_loop():
            while not self._stop_spinner.is_set():
                time.sleep(0.1)  # Update every 100ms
                with self.lock:
                    # Only refresh if we have active scans
                    has_active = any(
                        status == "scanning"
                        for _, _, _, _, status, _ in self.progress.values()
                    )
                    if has_active and self.lines_printed > 0:
                        self._spinner_idx = (self._spinner_idx + 1) % len(self.SPINNER_FRAMES)
                        self._refresh_display()

        self._spinner_thread = threading.Thread(target=spinner_loop, daemon=True)
        self._spinner_thread.start()

    def _clear_progress_area(self):
        """Clear the progress display area."""
        if self.lines_printed > 0:
            # Move up and clear each line
            for _ in range(self.lines_printed):
                sys.stdout.write(CURSOR_UP + CLEAR_LINE)
            sys.stdout.flush()

    def _format_elapsed(self, seconds: float) -> str:
        """Format elapsed time as mm:ss."""
        mins, secs = divmod(int(seconds), 60)
        return f"{mins}:{secs:02d}"

    def _render_progress(self):
        """Render the current progress state with spinners."""
        lines = []
        spinner = self.SPINNER_FRAMES[self._spinner_idx]
        lines.append(f"{Fore.CYAN}┌─ Scanning Progress:{Style.RESET_ALL}")

        current_time = time.time()
        for target_id in sorted(self.progress.keys()):
            ip, port, port_idx, total_ports, status, start_time = self.progress[target_id]
            elapsed = current_time - start_time if start_time else 0

            if status == "complete":
                line = f"{Fore.GREEN}│ [{target_id}/{self.total_targets}] {ip} → Complete ✓{Style.RESET_ALL}"
            elif status == "error":
                line = f"{Fore.RED}│ [{target_id}/{self.total_targets}] {ip} → Error ✗{Style.RESET_ALL}"
            else:
                # Active scan with spinner and elapsed time
                elapsed_str = self._format_elapsed(elapsed)
                line = f"{Fore.YELLOW}│ {spinner} [{target_id}/{self.total_targets}] {ip}:{port} → Scanning ({port_idx}/{total_ports}) [{elapsed_str}]{Style.RESET_ALL}"
            lines.append(line)

        lines.append(f"{Fore.CYAN}└{'─' * 50}{Style.RESET_ALL}")
        return lines

    def update(self, target_id: int, ip: str, port: int = 0, port_idx: int = 0, total_ports: int = 0, status: str = "scanning"):
        """Update progress for a target (thread-safe)."""
        with self.lock:
            # Preserve start_time if already tracking, else set new start time
            existing = self.progress.get(target_id)
            if existing and existing[4] == "scanning":
                start_time = existing[5]  # Keep existing start time
            else:
                start_time = time.time() if status == "scanning" else 0

            self.progress[target_id] = (ip, port, port_idx, total_ports, status, start_time)
            self._refresh_display()

    def _refresh_display(self):
        """Refresh the progress display in-place."""
        # Clear previous output
        self._clear_progress_area()

        # Render new progress
        lines = self._render_progress()

        # Print new progress
        for line in lines:
            print(line)

        self.lines_printed = len(lines)
        sys.stdout.flush()

    def finish(self):
        """Clear progress display when all scans complete."""
        self._stop_spinner.set()
        with self.lock:
            self._clear_progress_area()
            self.lines_printed = 0

# ───────── constants / tuning
CMD_TOUT, CURL_TOUT = 180, 15          # generic timeouts
TESTSSL_TOUT = 600                      # 10 minute timeout for testssl
PACE = 0.3                              # pause between ports to avoid FW throttling
VERIFY_SSL = False

# Preferred testssl.sh, then CLI "testssl", otherwise graceful skip
PREF = os.getenv("TESTSSL_PATH") or "/root/tools/testssl.sh/testssl.sh"
if os.path.isfile(PREF) and os.access(PREF, os.X_OK):
    TESTSSL_BIN = PREF
elif shutil.which("testssl"):
    TESTSSL_BIN = "testssl"
else:
    TESTSSL_BIN = None  # graceful skip

# ───────── predefined interesting ports
class P(Enum):
    HTTP = 80
    HTTPS = 443
    ALT_HTTPS = 10443
    HTTP1 = 8080
    HTTP2 = 8000
    HTTP3 = 8880
    SNMP = 161
    IKE1 = 500
    IKE_NAT = 4500
    DNS = 53
    MDNS = 5353
    SMTP25 = 25
    SMTP465 = 465
    SMTP587 = 587
    SMTP2525 = 2525
    SSH = 22
    NTP = 123

# ───────── basic logging (stdout only)
def setup_log(debug: bool):
    logging.basicConfig(
        level=logging.DEBUG if debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

# ───────── utility: input normalization
def strip_proto(u: str) -> str:
    return re.sub(r"^(https?://)?(www\.)?", "", u.lower())

def is_ip(a: str) -> bool:
    return re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", a) is not None

def resolve(h: str) -> str:
    return socket.gethostbyname(h)

def require_root():
    if os.geteuid() != 0:
        print(Fore.RED + "This tool needs root privileges. Re-run with sudo or as root." + Style.RESET_ALL)
        sys.exit(1)

# ───────── console formatting helpers
def banner(color, text: str):
    bar = color + "=" * 72 + Style.RESET_ALL
    write_output("\n" + bar)
    write_output(color + text + Style.RESET_ALL)
    write_output(bar)

def show_cmd(cmd):
    write_output(Fore.LIGHTBLUE_EX + "      Command: " + " ".join(cmd) + Style.RESET_ALL)

def ok(msg: str):
    write_output("      " + Fore.GREEN + msg + Style.RESET_ALL)

def warn(msg: str):
    write_output("      " + Fore.YELLOW + msg + Style.RESET_ALL)

def err(msg: str):
    write_output("      " + Fore.RED + msg + Style.RESET_ALL)

# ───────── dependency preflight
def tool_path(name: str) -> str | None:
    return shutil.which(name)

def check_dependencies(ports: list[int], args):
    """
    Hard requirements: nmap, nc, curl.
    Soft/conditional: dig (if DNS), snmp-check (if SNMP), ssh-audit (if SSH),
                      ike-scan (if 500), firefox (optional), testssl (optional).
    """
    missing = []
    for t in ("nmap", "nc", "curl"):
        if not tool_path(t):
            missing.append(t)
    if missing:
        banner(Fore.RED, "Missing required tools")
        for t in missing:
            err(f"Required tool '{t}' is not installed or not in PATH.")
            print("         " + f"Install suggestion: sudo apt-get install {t}")
        sys.exit(1)

    # Conditional/optional
    need_dns = P.DNS.value in ports or P.MDNS.value in ports
    need_snmp = P.SNMP.value in ports
    need_ssh  = P.SSH.value in ports
    need_ike  = P.IKE1.value in ports

    if need_dns and not tool_path("dig"):
        warn("Optional tool 'dig' not found (DNS scripts will be limited). Install: sudo apt-get install dnsutils")
    if need_snmp and not tool_path("snmp-check"):
        warn("Optional tool 'snmp-check' not found. Install: sudo apt-get install snmpcheck")
    if need_ssh and not tool_path("ssh-audit"):
        warn("Optional tool 'ssh-audit' not found. Install: pip install ssh-audit")
    if need_ike and not tool_path("ike-scan"):
        warn("Optional tool 'ike-scan' not found. Install: sudo apt-get install ike-scan")
    if TESTSSL_BIN is None:
        warn("testssl not found; TLS deep-dive will be skipped gracefully.")
    else:
        ok(f"testssl available: {TESTSSL_BIN}")

# ───────── command runners
def run_live(cmd, desc, timeout=CMD_TOUT) -> str:
    """
    Execute a command, streaming stdout live with nice formatting.
    Returns the complete (lowercased) output for programmatic checks.

    timeout=None -> run without any time limit.

    Uses a watchdog timer to enforce timeouts even when the process
    hangs without producing output (fixes testssl hanging issues).
    """
    banner(Fore.YELLOW, f"▶ {desc} (live)")
    show_cmd(cmd)
    buf = []
    timed_out = threading.Event()

    def watchdog(proc, timeout_secs):
        """Kill process if timeout elapses."""
        if timed_out.wait(timeout_secs):
            return  # Event was set, meaning we finished normally
        # Timeout elapsed - kill the process
        try:
            proc.kill()
            timed_out.set()
        except:
            pass

    try:
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        ) as p:
            # Start watchdog timer if timeout is set
            timer_thread = None
            if timeout is not None:
                timer_thread = threading.Thread(target=watchdog, args=(p, timeout), daemon=True)
                timer_thread.start()

            # Read output line by line
            for ln in p.stdout:
                if timed_out.is_set():
                    break
                line = ln.rstrip("\n")
                write_output("      " + line)
                buf.append(line)

            p.wait()

            # Signal watchdog to stop (if still running)
            timed_out.set()

            if p.returncode == -9 or (timer_thread and timed_out.is_set() and p.returncode != 0):
                # Process was killed by watchdog
                err("[TIMEOUT] The command took too long and was stopped.")
                warn("Tip: Re-run with --debug or run the command manually to investigate.")
            elif p.returncode == 0:
                ok("SUCCESS ✓")
            else:
                err(f"FAILED (exit code {p.returncode}).")
                tail = "\n".join(buf[-10:])
                if tail.strip():
                    warn("Last lines from the tool for context:")
                    for ln in tail.splitlines():
                        write_output("         " + ln)
                warn("Tip: Re-run with --debug to see more detail, or run the command manually.")
            return "\n".join(buf).lower()
    except FileNotFoundError:
        err(f"Cannot run '{cmd[0]}' because it was not found.")
        write_output("         " + f"Install suggestion: sudo apt-get install {cmd[0]}")
    except PermissionError:
        err(f"Permission denied when executing '{cmd[0]}'.")
        write_output("         " + "Tip: Ensure the file is executable (chmod +x) or run with sudo/root.")
    except Exception as e:
        err(f"Unexpected problem while running the command: {e}")
        warn("Tip: Re-run with --debug for additional diagnostics.")
    return ""

def run_testssl(args: list[str], desc: str) -> str:
    """
    Wrapper around testssl so the scan never crashes nor prints noisy errors
    if the binary is not present. Uses 10 minute timeout.
    """
    if TESTSSL_BIN is None:
        warn("Skipping testssl: binary not found on this system.")
        return ""
    full_cmd = [TESTSSL_BIN, *args]
    return run_live(full_cmd, desc, timeout=TESTSSL_TOUT)

# ───────── helpers (net/web)
def nc_probe(host, port):
    return run_live(["nc", "-vnz", "-w", "2", host, str(port)],
                    f"netcat probe {port}", 5)

def curl_hdr(proto, host, port):
    return run_live(["curl", "-I", "-k", f"{proto}://{host}:{port}"],
                    f"curl -I {proto}://{host}:{port}", CURL_TOUT)

def http_descr(code: int) -> str:
    return f"{HTTPStatus(code).phrase} ({code})"

# ───────── container
class Scanner:
    def __init__(self, target: str, args):
        self.tgt = target
        self.a = args
        self.recommended_urls = []  # URLs to visit (displayed in summary instead of auto-opening)

# ───────── WEB helpers
def webpage_visibility(sc: Scanner, port: int, proto: str):
    """
    If website appears reachable, collect URLs for summary display
    and print robots.txt contents. URLs are displayed in the final summary
    instead of auto-opening Firefox windows.
    """
    url = f"{proto}://{sc.tgt}:{port}"
    robots_url = f"{url}/robots.txt"

    try:
        r = requests.get(url, timeout=(5, 10), verify=VERIFY_SSL)
        write_output("      Main page -> " + http_descr(r.status_code))
        if r.status_code == 200:
            sc.recommended_urls.append(("Main page", url))
            ok(f"[+] Main page reachable: {url}")
    except requests.RequestException as e:
        warn(f"Could not reach {url}: {e}")
        return

    try:
        r = requests.get(robots_url, timeout=(5, 10), verify=VERIFY_SSL)
        write_output("      robots.txt -> " + http_descr(r.status_code))
        if r.status_code == 200 and r.text.strip():
            sc.recommended_urls.append(("robots.txt", robots_url))
            ok(f"[+] robots.txt found: {robots_url}")
            write_output("      " + Fore.MAGENTA + "robots.txt contents:" + Style.RESET_ALL)
            for ln in r.text.splitlines():
                write_output("         " + ln)
    except requests.RequestException as e:
        warn(f"Could not fetch robots.txt at {robots_url}: {e}")

def display_webpage_summary(sc: Scanner):
    """
    Display a summary of all recommended URLs to visit.
    This replaces auto-opening Firefox windows.
    """
    if not sc.recommended_urls:
        return

    write_output("")
    banner(Fore.MAGENTA, f"WEBPAGES TO REVIEW — {sc.tgt}")
    write_output(f"      {Fore.CYAN}The following pages are reachable and may be worth reviewing:{Style.RESET_ALL}")
    write_output("")
    for idx, (page_type, url) in enumerate(sc.recommended_urls, 1):
        write_output(f"      {Fore.WHITE}{idx}. [{page_type}]{Style.RESET_ALL} {Fore.GREEN}{url}{Style.RESET_ALL}")
    write_output("")
    write_output(f"      {Fore.YELLOW}Tip: Copy URLs above or run with --no-firefox to skip this check entirely{Style.RESET_ALL}")

# ───────── per-port handlers
def h_ssh(sc: Scanner, port: int):
    nc_probe(sc.tgt, port)
    run_live(["ssh-audit", f"{sc.tgt}:{port}"], "ssh-audit")
    run_live(["nmap", "-sC", "-sV", "-sU", "-Pn", "-p", str(port), sc.tgt],
             "nmap SSH scripts & version")

def h_smtp(sc: Scanner, port: int):
    nc_probe(sc.tgt, port)
    run_testssl(["-t", "smtp", f"{sc.tgt}:{port}"], "testssl SMTP mode")

def h_dns(sc: Scanner, port: int):
    run_live(["dig", "any", "+qr", f"@{sc.tgt}"], "dig ANY")
    run_live(["nmap", "--script=dns-service-discovery", "-p", "53", sc.tgt],
             "nmap dns-service-discovery 53")
    run_live(["nmap", "--script=dns-service-discovery", "-p", "5353", sc.tgt],
             "nmap dns-service-discovery 5353")

def h_ntp(sc: Scanner, port: int):
    run_live(["nmap", "-sU", "-sV", "--script",
              "ntp* and (discovery or vuln) and not (dos or brute)",
              "-p", "123", sc.tgt],
             "nmap NTP scripts")

def h_snmp(sc: Scanner, port: int):
    # Always run even if nc said closed
    run_live(["nmap", "-sC", "-sV", "-sU", "-Pn", "-p", "161", sc.tgt], "nmap SNMP")
    for comm in ("public", "private"):
        run_live(["snmp-check", sc.tgt, "-c", comm, "-v2c"], f"snmp-check {comm}")

def h_ike(sc: Scanner, port: int):
    # Only port 500 gets the ike-scan trilogy. 4500 is generic.
    if port == 500:
        for cmd in (
            ["ike-scan", sc.tgt],
            ["ike-scan", sc.tgt, "-M", "-2"],
            ["ike-scan", sc.tgt, "-M", "-A", "--id=GroupVPN"],
        ):
            run_live(cmd, " ".join(cmd))

def h_web(sc: Scanner, port: int, proto: str):
    # explicit curl -I for web ports
    curl_hdr(proto, sc.tgt, port)
    nc_probe(sc.tgt, port)

    # Fast path: if "443" appears anywhere in the port number
    if "443" in str(port):
        run_testssl([f"{sc.tgt}:{port}"], "testssl.sh")
        webpage_visibility(sc, port, proto)
        return

    # Otherwise full web flow
    run_live(["nmap", "-sC", "-sV", "-sU", "-Pn", "-p", str(port), sc.tgt],
             f"nmap web scan ({port})")
    if port != 80:
        run_testssl([f"{sc.tgt}:{port}"], "testssl.sh")
    webpage_visibility(sc, port, proto)

# ───────── mapping of well-known ports to their handlers (4500 intentionally generic)
HANDLERS = {
    P.SSH.value: h_ssh,
    P.SMTP25.value: h_smtp,
    P.SMTP465.value: h_smtp,
    P.SMTP587.value: h_smtp,
    P.SMTP2525.value: h_smtp,
    P.DNS.value: h_dns,
    P.NTP.value: h_ntp,
    P.SNMP.value: h_snmp,
    P.IKE1.value: h_ike,
}

# ───────── generic flow
def generic(sc: Scanner, port: int):
    banner(Fore.BLUE, f"[GENERIC] Port {port}")
    nc_probe(sc.tgt, port)

    # If "443" anywhere in port number, go straight to testssl (skip nmap)
    if "443" in str(port) and not sc.a.no_ssl:
        run_testssl([f"{sc.tgt}:{port}"], "testssl.sh")
        # If this is a classic web port family, do visibility
        if port in (P.HTTP.value, P.HTTPS.value, P.HTTP1.value, P.HTTP2.value, P.HTTP3.value):
            proto = "https"
            curl_hdr(proto, sc.tgt, port)
            webpage_visibility(sc, port, proto)
        return

    nmap_out = run_live(
        ["nmap", "-Pn", "-sV", "-T4", "-p", str(port), sc.tgt],
        "nmap service/version scan"
    )

    # Only consider service lines for THIS port.
    svc_lines = "\n".join(
        l for l in nmap_out.splitlines()
        if re.match(rf"^{port}/(tcp|udp)\s+open", l, flags=re.IGNORECASE)
    )

    # Web-ish?
    is_web = any(k in svc_lines for k in ("http", "ssl/http", "https"))

    # TLS decision
    tls = (
        "https" in svc_lines
        or re.search(r"\bssl[/-]", svc_lines)
        or "tls" in svc_lines
    )

    # Avoid pointless testssl on some cases (IKE, reverse-ssl etc.)
    if "reverse-ssl" in svc_lines or port in (500, 4500):
        tls = False

    if tls and not sc.a.no_ssl:
        run_testssl([f"{sc.tgt}:{port}"], "testssl.sh")

    # Web visibility checks for classic web ports OR detected web banners
    if (not sc.a.no_web) and (
        port in (P.HTTP.value, P.HTTPS.value, P.HTTP1.value, P.HTTP2.value, P.HTTP3.value)
        or is_web
    ):
        proto = "https" if tls else "http"
        curl_hdr(proto, sc.tgt, port)
        webpage_visibility(sc, port, proto)

# ───────── dispatcher
def scan_port(sc: Scanner, port: int):
    if port == P.HTTP.value:
        banner(Fore.MAGENTA, "[WEB80] Detailed web scan")
        h_web(sc, 80, "http")
    elif "443" in str(port):
        banner(Fore.MAGENTA, f"[WEB{port}] Detailed web scan")
        h_web(sc, port, "https")
    else:
        (HANDLERS.get(port) or generic)(sc, port)

# ───────── CLI / main
def expand(spec: str):
    out = set()
    for seg in spec.split(","):
        seg = seg.strip()
        if "-" in seg:
            lo, hi = map(int, seg.split("-", 1))
            out.update(range(lo, hi + 1))
        else:
            out.add(int(seg))
    return sorted(out)

def cli():
    ap = argparse.ArgumentParser(description="EVA — Banner-style live-output scanner")
    ap.add_argument("--target", help="IP or hostname")
    ap.add_argument("--ports", help="Comma list and/or ranges (e.g., 80,443,1-1024)")
    ap.add_argument("--interactive", "-i", action="store_true",
                    help="Interactive mode: input multiple IPs and ports, scan concurrently")
    ap.add_argument("--no-ssl", action="store_true", help="Skip all TLS/testssl scans")
    ap.add_argument("--no-web", action="store_true", help="Skip curl/HTTP and webpage visibility checks")
    ap.add_argument("--no-firefox", action="store_true", help="Skip webpage visibility checks (legacy flag, same as --no-web for URLs)")
    ap.add_argument("--debug", action="store_true", help="Verbose internal logging to stdout")
    args = ap.parse_args()

    # Validation
    if not args.interactive and (not args.target or not args.ports):
        ap.error("--target and --ports are required unless using --interactive mode")
    if args.interactive and (args.target or args.ports):
        ap.error("--interactive mode does not use --target or --ports arguments")

    return args

def collect_targets_interactive():
    """
    Interactively collect multiple targets and their ports from user input.
    Returns a list of tuples: [(target, port_spec), ...]
    """
    targets = []
    print(Fore.CYAN + "\n" + "=" * 72)
    print("EVA Interactive Mode — Enter targets and ports")
    print("=" * 72 + Style.RESET_ALL)
    print(Fore.YELLOW + "\nInstructions:")
    print("  • Enter IP or hostname for each target")
    print("  • Enter ports as comma-separated list and/or ranges (e.g., 80,443,1-1024)")
    print("  • Type 'done' when finished adding targets")
    print("  • Type 'quit' to cancel" + Style.RESET_ALL)

    target_num = 1
    while True:
        print(f"\n{Fore.CYAN}[Target #{target_num}]{Style.RESET_ALL}")

        # Get IP/hostname
        target_input = input(f"  Enter IP or hostname (or 'done' to start scan): ").strip()

        if target_input.lower() == 'done':
            if not targets:
                print(Fore.RED + "  No targets entered. Please enter at least one target." + Style.RESET_ALL)
                continue
            break

        if target_input.lower() == 'quit':
            print(Fore.YELLOW + "\nCancelled by user." + Style.RESET_ALL)
            sys.exit(0)

        if not target_input:
            print(Fore.RED + "  Target cannot be empty. Try again." + Style.RESET_ALL)
            continue

        # Get ports
        ports_input = input(f"  Enter ports for {target_input}: ").strip()

        if not ports_input:
            print(Fore.RED + "  Ports cannot be empty. Try again." + Style.RESET_ALL)
            continue

        # Validate ports by attempting to expand
        try:
            port_list = expand(ports_input)
            if not port_list:
                print(Fore.RED + "  No valid ports found. Try again." + Style.RESET_ALL)
                continue
        except Exception as e:
            print(Fore.RED + f"  Invalid port specification: {e}" + Style.RESET_ALL)
            continue

        targets.append((target_input, ports_input))
        print(Fore.GREEN + f"  ✓ Added {target_input} with {len(port_list)} port(s)" + Style.RESET_ALL)
        target_num += 1

    return targets

def scan_target(target: str, port_spec: str, args, progress_tracker: ProgressTracker, target_id: int, total_targets: int):
    """
    Scan a single target and return the results as a string.
    Uses thread-local output capturing to prevent interleaved output from concurrent scans.
    Provides real-time progress updates via the ProgressTracker.
    """
    # Resolve target
    host = strip_proto(target)
    try:
        tgt = host if is_ip(host) else resolve(host)
    except Exception as e:
        progress_tracker.update(target_id, host, status="error")
        return f"\n{Fore.RED}[ERROR] Could not resolve '{host}': {e}{Style.RESET_ALL}\n"

    # Expand ports
    try:
        port_list = expand(port_spec)
    except Exception as e:
        progress_tracker.update(target_id, tgt, status="error")
        return f"\n{Fore.RED}[ERROR] Invalid port specification for {target}: {e}{Style.RESET_ALL}\n"

    # Initial progress update
    progress_tracker.update(target_id, tgt, port_list[0] if port_list else 0, 1, len(port_list), "scanning")

    # Build the scanner
    sc = Scanner(tgt, args)

    # Output header
    output_parts = []
    output_parts.append(f"\n{Fore.CYAN}{'=' * 72}")
    output_parts.append(f"Target: {tgt}   Ports: {port_spec}")
    output_parts.append(f"{'=' * 72}{Style.RESET_ALL}\n")

    try:
        # Start thread-local output capture
        start_capture()

        # Scan each port with progress updates
        for idx, p in enumerate(port_list, 1):
            try:
                # Progress update via tracker (uses real stdout, not affected by capture)
                progress_tracker.update(target_id, tgt, p, idx, len(port_list), "scanning")

                scan_port(sc, p)
                time.sleep(PACE)
            except Exception as e:
                banner(Fore.RED, f"Port {p} — unexpected error")
                err(f"Something went wrong while scanning port {p}: {e}")

        # Display webpage summary (still capturing output)
        display_webpage_summary(sc)

        # Stop capture and get captured content
        captured_content = stop_capture()
        output_parts.append(captured_content)

        output_parts.append(f"\n{Fore.GREEN}{'=' * 72}")
        output_parts.append(f"COMPLETED: {tgt}")
        output_parts.append(f"{'=' * 72}{Style.RESET_ALL}\n")

        # Mark as complete
        progress_tracker.update(target_id, tgt, status="complete")

    except Exception as e:
        # Make sure capture is stopped on error
        stop_capture()
        output_parts.append(f"\n{Fore.RED}[FATAL ERROR] Scan failed for {tgt}: {e}{Style.RESET_ALL}\n")
        progress_tracker.update(target_id, tgt, status="error")

    return "\n".join(output_parts)

def ask_processing_mode():
    """
    Ask user whether to run scans in batches or all at once.
    Returns: 'batch' or 'all'
    """
    print(f"\n{Fore.CYAN}{'=' * 72}")
    print("SELECT PROCESSING MODE")
    print(f"{'=' * 72}{Style.RESET_ALL}\n")
    print(f"  {Fore.YELLOW}[b]{Style.RESET_ALL} Batch mode — Run 5 IPs at a time (safer for large scans)")
    print(f"  {Fore.YELLOW}[a]{Style.RESET_ALL} All at once — Run all IPs simultaneously (faster but more resource intensive)")
    print()

    while True:
        choice = input(f"  {Fore.CYAN}Enter choice [b/a]: {Style.RESET_ALL}").strip().lower()
        if choice in ('b', 'batch'):
            return 'batch'
        elif choice in ('a', 'all'):
            return 'all'
        else:
            print(Fore.RED + "  Invalid choice. Please enter 'b' for batch or 'a' for all at once." + Style.RESET_ALL)


def display_final_summary(targets, results):
    """
    Display a final summary of all scanned IPs and their ports.
    """
    print(f"\n{Fore.CYAN}{'=' * 72}")
    print("FINAL SUMMARY — All Targets and Ports")
    print(f"{'=' * 72}{Style.RESET_ALL}\n")

    print(f"  {Fore.WHITE}{'Target':<30} {'Ports':<40}{Style.RESET_ALL}")
    print(f"  {'-' * 30} {'-' * 40}")

    for idx, (tgt, port_spec) in enumerate(targets):
        # Resolve target for display
        host = strip_proto(tgt)
        try:
            resolved = host if is_ip(host) else resolve(host)
            display_name = f"{host}" if host == resolved else f"{host} ({resolved})"
        except:
            display_name = host
            resolved = host

        # Expand ports for count
        try:
            port_list = expand(port_spec)
            port_count = len(port_list)
            # Show first few ports and count
            if port_count <= 5:
                ports_display = port_spec
            else:
                first_ports = ", ".join(str(p) for p in port_list[:3])
                ports_display = f"{first_ports}... ({port_count} total)"
        except:
            ports_display = port_spec

        # Determine status from results
        result = results.get(idx, "")
        if "COMPLETED" in result:
            status = f"{Fore.GREEN}✓{Style.RESET_ALL}"
        elif "ERROR" in result:
            status = f"{Fore.RED}✗{Style.RESET_ALL}"
        else:
            status = f"{Fore.YELLOW}?{Style.RESET_ALL}"

        print(f"  {status} {display_name:<28} {ports_display:<40}")

    print()
    print(f"  {Fore.CYAN}Total targets scanned: {len(targets)}{Style.RESET_ALL}")

    # Count successes and failures
    successes = sum(1 for r in results.values() if "COMPLETED" in r)
    failures = sum(1 for r in results.values() if "ERROR" in r)

    if successes > 0:
        print(f"  {Fore.GREEN}Successful: {successes}{Style.RESET_ALL}")
    if failures > 0:
        print(f"  {Fore.RED}Failed: {failures}{Style.RESET_ALL}")

    print()


def run_interactive_mode(args):
    """
    Run EVA in interactive mode: collect multiple targets, scan concurrently, display organized results.
    Supports batch mode (5 IPs at a time) or all-at-once mode.
    """
    # Collect targets
    targets = collect_targets_interactive()

    if not targets:
        print(Fore.RED + "\nNo targets to scan. Exiting." + Style.RESET_ALL)
        sys.exit(0)

    # Show summary
    print(f"\n{Fore.CYAN}{'=' * 72}")
    print(f"Targets collected: {len(targets)}")
    print(f"{'=' * 72}{Style.RESET_ALL}\n")

    for idx, (tgt, ports) in enumerate(targets, 1):
        print(f"  {idx}. {tgt} → {ports}")

    # Ask user for processing mode
    processing_mode = ask_processing_mode()

    # Check dependencies for all ports
    all_ports = set()
    for _, port_spec in targets:
        try:
            all_ports.update(expand(port_spec))
        except:
            pass
    check_dependencies(sorted(all_ports), args)

    # Run scans based on selected mode
    output_lock = Lock()
    results = {}  # Store results with original order
    total_targets = len(targets)

    if processing_mode == 'batch':
        # Batch mode: process 5 IPs at a time
        BATCH_SIZE = 5
        num_batches = (total_targets + BATCH_SIZE - 1) // BATCH_SIZE

        print(f"\n{Fore.CYAN}{'=' * 72}")
        print(f"BATCH MODE — Processing {total_targets} targets in batches of {BATCH_SIZE}")
        print(f"Total batches: {num_batches}")
        print(f"{'=' * 72}{Style.RESET_ALL}\n")

        for batch_num in range(num_batches):
            start_idx = batch_num * BATCH_SIZE
            end_idx = min(start_idx + BATCH_SIZE, total_targets)
            batch_targets = targets[start_idx:end_idx]
            batch_size = len(batch_targets)

            print(f"\n{Fore.YELLOW}{'─' * 72}")
            print(f"BATCH {batch_num + 1}/{num_batches} — Targets {start_idx + 1} to {end_idx}")
            print(f"{'─' * 72}{Style.RESET_ALL}\n")

            # Create progress tracker for this batch
            progress_tracker = ProgressTracker(batch_size, output_lock)

            with ThreadPoolExecutor(max_workers=batch_size) as executor:
                # Submit all tasks in this batch
                future_to_idx = {
                    executor.submit(scan_target, tgt, ports, args, progress_tracker, local_idx + 1, batch_size): global_idx
                    for local_idx, (global_idx, (tgt, ports)) in enumerate(
                        (start_idx + i, batch_targets[i]) for i in range(batch_size)
                    )
                }

                # Collect results as they complete
                for future in as_completed(future_to_idx):
                    idx = future_to_idx[future]
                    try:
                        result = future.result()
                        results[idx] = result
                    except Exception as e:
                        results[idx] = f"\n{Fore.RED}[ERROR] Failed to scan target #{idx + 1}: {e}{Style.RESET_ALL}\n"

            # Clear progress display after batch
            progress_tracker.finish()

            print(f"\n{Fore.GREEN}Batch {batch_num + 1} complete.{Style.RESET_ALL}")

    else:
        # All at once mode: run all IPs simultaneously
        print(f"\n{Fore.CYAN}{'=' * 72}")
        print(f"ALL AT ONCE MODE — Running {total_targets} targets simultaneously")
        print(f"{'=' * 72}{Style.RESET_ALL}\n")

        # Create progress tracker for in-place updates
        progress_tracker = ProgressTracker(total_targets, output_lock)

        with ThreadPoolExecutor(max_workers=total_targets) as executor:
            # Submit all tasks with target IDs
            future_to_idx = {
                executor.submit(scan_target, tgt, ports, args, progress_tracker, idx + 1, total_targets): idx
                for idx, (tgt, ports) in enumerate(targets)
            }

            # Collect results as they complete
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    result = future.result()
                    results[idx] = result
                except Exception as e:
                    results[idx] = f"\n{Fore.RED}[ERROR] Failed to scan target #{idx + 1}: {e}{Style.RESET_ALL}\n"

        # Clear the progress display before showing results
        progress_tracker.finish()

    # Display results in order
    print(f"\n\n{Fore.CYAN}{'=' * 72}")
    print("SCAN RESULTS (in order of input)")
    print(f"{'=' * 72}{Style.RESET_ALL}\n")

    for idx in sorted(results.keys()):
        print(results[idx])

    # Display final summary of all IPs and ports
    display_final_summary(targets, results)

    banner(Fore.GREEN, "ALL SCANS COMPLETE")

def main():
    require_root()
    args = cli()
    setup_log(args.debug)

    signal.signal(signal.SIGINT, lambda *_: sys.exit("\nInterrupted by user."))

    # Handle interactive mode
    if args.interactive:
        run_interactive_mode(args)
        return

    # Normal mode (single target)
    host = strip_proto(args.target)
    try:
        tgt = host if is_ip(host) else resolve(host)
    except Exception as e:
        banner(Fore.RED, "Target resolution error")
        err(f"Could not resolve '{host}': {e}")
        print("         " + "Check DNS/host spelling or try using the raw IP address.")
        sys.exit(1)

    banner(Fore.CYAN, f"Scanning target: {tgt}   Ports: {args.ports}")

    port_list = expand(args.ports)
    check_dependencies(port_list, args)

    sc = Scanner(tgt, args)

    for p in tqdm(port_list, desc="Ports", unit="port", ncols=80, colour="cyan"):
        try:
            scan_port(sc, p)
        except Exception as e:
            banner(Fore.RED, f"Port {p} — unexpected error")
            err(f"Something went wrong while scanning port {p}: {e}")
            print("         " + "Tip: Re-run with --debug for more details, or try scanning this port manually.")
        time.sleep(PACE)

    # Display webpage summary instead of auto-opening Firefox
    display_webpage_summary(sc)

    banner(Fore.GREEN, "SCAN COMPLETE")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:
        banner(Fore.RED, "Fatal error")
        err(f"The scan encountered a fatal error: {e}")
        print("         " + "Tip: Re-run with --debug to view internal diagnostics.")
        sys.exit(1)
