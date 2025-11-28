#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  Author :  Ryan Kucher
#  Version:  8.4
#  Date   :  2025-11-28
# ─────────────────────────────────────────────────────────────
"""
EVA Scanner v8.4 — Concurrent multi-target scanner with live output and real-time progress.

Highlights
----------
• Human-friendly errors and guidance (no log files, no stack traces by default).
• Live, colorized streaming of command output with clear section headers.
• Interactive mode (--interactive or -i): scan multiple IPs concurrently with organized output.
  - Multiple IPs scan simultaneously (concurrent threads)
  - Ports per IP scan sequentially (like original single-target mode)
  - Real-time progress updates showing which IP:port is being scanned
  - Clean organized output at the end with all results in order
• Fast-path TLS: if the port number contains "443" anywhere (e.g., 443, 1443, 4433, 10443),
  run testssl immediately and skip nmap for speed.
• Smarter TLS trigger in generic flow (uses THIS port's service line only; skips reverse-ssl, IKE).
• Web visibility helper: if site is reachable, auto-open in Firefox (unless --no-firefox)
  and print robots.txt contents, opening it too if present.
• SNMP: still runs even if netcat reports closed; nmap SNMP + snmp-check (public/private).
• IKE: only port 500 runs the ike-scan trilogy; port 4500 stays generic.
• testssl runs non-interactively with timeout to prevent hangs on non-TLS servers.

Requirements (Kali/Debian)
--------------------------
sudo apt-get install nmap netcat-traditional curl dnsutils snmpcheck ssh-audit ike-scan firefox-esr
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

# Thread-local storage for output redirection in concurrent scans
import threading
_thread_local = threading.local()

# Spinner animation frames
SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']

# ───────── constants / tuning
CMD_TOUT, CURL_TOUT = 180, 15          # generic timeouts
TESTSSL_TOUT = 300                      # testssl timeout (5 minutes)
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
def _write(msg: str):
    """Write to thread-local output file if set, otherwise stdout"""
    if hasattr(_thread_local, 'output_file'):
        _thread_local.output_file.write(msg + "\n")
    else:
        print(msg)

def banner(color, text: str):
    bar = color + "=" * 72 + Style.RESET_ALL
    _write("\n" + bar)
    _write(color + text + Style.RESET_ALL)
    _write(bar)

def show_cmd(cmd):
    _write(Fore.LIGHTBLUE_EX + "      Command: " + " ".join(cmd) + Style.RESET_ALL)

def ok(msg: str):
    _write("      " + Fore.GREEN + msg + Style.RESET_ALL)

def warn(msg: str):
    _write("      " + Fore.YELLOW + msg + Style.RESET_ALL)

def err(msg: str):
    _write("      " + Fore.RED + msg + Style.RESET_ALL)

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
    if not args.no_firefox and not tool_path("firefox"):
        warn("Firefox not found; pages will not be auto-opened. Install: sudo apt-get install firefox-esr")
    if TESTSSL_BIN is None:
        warn("testssl not found; TLS deep-dive will be skipped gracefully.")
    else:
        ok(f"testssl available: {TESTSSL_BIN}")

# ───────── command runners
def run_live(cmd, desc, timeout=CMD_TOUT, silent=False, output_file=None) -> str:
    """
    Execute a command, streaming stdout live with nice formatting.
    Returns the complete (lowercased) output for programmatic checks.

    timeout=None -> run without any time limit.
    silent=True -> capture output without printing (for concurrent scans)
    output_file -> file-like object to write formatted output to (instead of stdout)
    """
    # Check for thread-local output file (used in concurrent scans)
    if output_file is None and hasattr(_thread_local, 'output_file'):
        output_file = _thread_local.output_file
        silent = True  # Automatically enable silent mode for thread-local output

    def write_output(msg):
        """Helper to write output to file or stdout"""
        if output_file:
            output_file.write(msg + "\n")
        elif not silent:
            print(msg)

    if not silent:
        banner(Fore.YELLOW, f"▶ {desc} (live)")
        show_cmd(cmd)
    else:
        write_output(f"\n{Fore.YELLOW}{'=' * 72}")
        write_output(f"▶ {desc} (live)")
        write_output(f"{'=' * 72}{Style.RESET_ALL}")
        write_output(Fore.LIGHTBLUE_EX + "      Command: " + " ".join(cmd) + Style.RESET_ALL)

    buf = []
    start = time.time()
    try:
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        ) as p:
            for ln in p.stdout:
                line = ln.rstrip("\n")
                write_output("      " + line)
                buf.append(line)
                if timeout is not None and (time.time() - start) > timeout:
                    p.kill()
                    write_output("      " + Fore.RED + "[TIMEOUT] The command took too long and was stopped." + Style.RESET_ALL)
                    write_output("      " + Fore.YELLOW + "Tip: Re-run with --debug or run the command manually to investigate." + Style.RESET_ALL)
                    break
            p.wait()
            if p.returncode == 0:
                write_output("      " + Fore.GREEN + "SUCCESS ✓" + Style.RESET_ALL)
            else:
                write_output("      " + Fore.RED + f"FAILED (exit code {p.returncode})." + Style.RESET_ALL)
                tail = "\n".join(buf[-10:])
                if tail.strip():
                    write_output("      " + Fore.YELLOW + "Last lines from the tool for context:" + Style.RESET_ALL)
                    for ln in tail.splitlines():
                        write_output("         " + ln)
                write_output("      " + Fore.YELLOW + "Tip: Re-run with --debug to see more detail, or run the command manually." + Style.RESET_ALL)
            return "\n".join(buf).lower()
    except FileNotFoundError:
        write_output("      " + Fore.RED + f"Cannot run '{cmd[0]}' because it was not found." + Style.RESET_ALL)
        write_output("         " + f"Install suggestion: sudo apt-get install {cmd[0]}")
    except PermissionError:
        write_output("      " + Fore.RED + f"Permission denied when executing '{cmd[0]}'." + Style.RESET_ALL)
        write_output("         " + "Tip: Ensure the file is executable (chmod +x) or run with sudo/root.")
    except Exception as e:
        write_output("      " + Fore.RED + f"Unexpected problem while running the command: {e}" + Style.RESET_ALL)
        write_output("      " + Fore.YELLOW + "Tip: Re-run with --debug for additional diagnostics." + Style.RESET_ALL)
    return ""

def run_testssl(args: list[str], desc: str) -> str:
    """
    Wrapper around testssl so the scan never crashes nor prints noisy errors
    if the binary is not present. Includes timeout to prevent hangs on non-TLS servers.
    """
    if TESTSSL_BIN is None:
        warn("Skipping testssl: binary not found on this system.")
        return ""
    # Add flags to suppress warnings and make non-interactive
    # --warnings=off: suppress interactive prompts when TLS not detected
    # --batch: non-interactive mode
    full_cmd = [TESTSSL_BIN, "--warnings=off", "--batch", *args]
    return run_live(full_cmd, desc, timeout=TESTSSL_TOUT)

# ───────── helpers (net/web)
def nc_probe(host, port):
    return run_live(["nc", "-vnz", "-w", "2", host, str(port)],
                    f"netcat probe {port}", 5)

def curl_hdr(proto, host, port):
    return run_live(["curl", "-I", "-k", f"{proto}://{host}:{port}"],
                    f"curl -I {proto}://{host}:{port}", CURL_TOUT)

def open_firefox(url: str, suppress: bool):
    if suppress:
        return
    try:
        subprocess.Popen(
            ["firefox", "-new-window", url],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        ok(f"[+] Opened Firefox: {url}")
    except FileNotFoundError:
        warn("Firefox not found; cannot open the page automatically.")
    except Exception as e:
        warn(f"Could not open Firefox for {url}: {e}")

def http_descr(code: int) -> str:
    return f"{HTTPStatus(code).phrase} ({code})"

# ───────── container
class Scanner:
    def __init__(self, target: str, args):
        self.tgt = target
        self.a = args

# ───────── WEB helpers
def webpage_visibility(sc: Scanner, port: int, proto: str):
    """
    If website appears reachable, open Firefox on / and /robots.txt
    and print robots.txt contents.
    """
    url = f"{proto}://{sc.tgt}:{port}"
    robots_url = f"{url}/robots.txt"

    try:
        r = requests.get(url, timeout=(5, 10), verify=VERIFY_SSL)
        print("      Main page ->", http_descr(r.status_code))
        if r.status_code == 200:
            open_firefox(url, sc.a.no_firefox)
    except requests.RequestException as e:
        warn(f"Could not reach {url}: {e}")
        return

    try:
        r = requests.get(robots_url, timeout=(5, 10), verify=VERIFY_SSL)
        print("      robots.txt ->", http_descr(r.status_code))
        if r.status_code == 200 and r.text.strip():
            open_firefox(robots_url, sc.a.no_firefox)
            print("      " + Fore.MAGENTA + "robots.txt contents:" + Style.RESET_ALL)
            for ln in r.text.splitlines():
                print("         " + ln)
    except requests.RequestException as e:
        warn(f"Could not fetch robots.txt at {robots_url}: {e}")

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
    ap.add_argument("--no-web", action="store_true", help="Skip curl/HTTP and Firefox actions")
    ap.add_argument("--no-firefox", action="store_true", help="Do not launch Firefox even if reachable")
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

class ProgressTracker:
    """Live progress tracker with dynamic updating display"""
    def __init__(self, total_targets):
        self.total_targets = total_targets
        self.statuses = {}  # target_id -> {"ip": str, "status": str, "port": int, "current": int, "total": int}
        self.lock = Lock()
        self.spinner_idx = 0
        self.lines_printed = 0
        self.active = True

    def update(self, target_id, ip, status, port=None, current=0, total=0):
        """Update status for a target"""
        with self.lock:
            self.statuses[target_id] = {
                "ip": ip,
                "status": status,
                "port": port,
                "current": current,
                "total": total
            }

    def render(self):
        """Render the current status display"""
        with self.lock:
            # Clear previous lines (move cursor up and clear each line)
            if self.lines_printed > 0:
                # Move cursor up by the number of lines we printed
                print(f'\033[{self.lines_printed}A', end='')
                # Clear from cursor to end of screen
                print('\033[J', end='')

            lines = []
            spinner = SPINNER_FRAMES[self.spinner_idx % len(SPINNER_FRAMES)]
            self.spinner_idx += 1

            # Header (no leading newline)
            lines.append(f"{Fore.CYAN}{spinner} Scanning Progress:{Style.RESET_ALL}")
            lines.append("")

            # Status for each target
            for target_id in sorted(self.statuses.keys()):
                s = self.statuses[target_id]
                ip = s["ip"]
                status = s["status"]
                port = s["port"]
                current = s["current"]
                total = s["total"]

                if status == "starting":
                    color = Fore.CYAN
                    msg = f"[{target_id}/{self.total_targets}] {ip} → Starting ({total} ports)"
                elif status == "scanning":
                    color = Fore.YELLOW
                    msg = f"[{target_id}/{self.total_targets}] {ip}:{port} → Scanning ({current}/{total})"
                elif status == "complete":
                    color = Fore.GREEN
                    msg = f"[{target_id}/{self.total_targets}] {ip} → Complete ✓"
                elif status == "error":
                    color = Fore.RED
                    msg = f"[{target_id}/{self.total_targets}] {ip} → Error ✗"
                else:
                    color = Fore.WHITE
                    msg = f"[{target_id}/{self.total_targets}] {ip} → {status}"

                lines.append(f"  {color}{msg}{Style.RESET_ALL}")

            # Print all lines with flush to ensure immediate display
            for line in lines:
                print(line)
            sys.stdout.flush()
            self.lines_printed = len(lines)

    def stop(self):
        """Stop the tracker and clear the display"""
        self.active = False
        with self.lock:
            # Clear all status lines
            if self.lines_printed > 0:
                # Move cursor up by the number of lines we printed
                print(f'\033[{self.lines_printed}A', end='')
                # Clear from cursor to end of screen
                print('\033[J', end='', flush=True)

def scan_target(target: str, port_spec: str, args, output_lock: Lock, target_id: int, total_targets: int, progress_tracker=None):
    """
    Scan a single target and capture all output.
    Scans ports sequentially with simple progress updates.
    Returns captured output for organized display at the end.
    """
    from io import StringIO

    # Resolve target
    host = strip_proto(target)
    try:
        tgt = host if is_ip(host) else resolve(host)
    except Exception as e:
        return f"\n{Fore.RED}[ERROR] Could not resolve '{host}': {e}{Style.RESET_ALL}\n"

    # Expand ports
    try:
        port_list = expand(port_spec)
    except Exception as e:
        if progress_tracker:
            progress_tracker.update(target_id, host, "error", total=0)
        return f"\n{Fore.RED}[ERROR] Invalid port specification for {target}: {e}{Style.RESET_ALL}\n"

    # Initial progress update
    if progress_tracker:
        progress_tracker.update(target_id, tgt, "starting", total=len(port_list))

    # Build the scanner
    sc = Scanner(tgt, args)

    # Set up thread-local output capture
    output_buffer = StringIO()
    _thread_local.output_file = output_buffer

    output_buffer.write(f"\n{Fore.CYAN}{'=' * 72}\n")
    output_buffer.write(f"Target {target_id}/{total_targets}: {tgt}   Ports: {port_spec}\n")
    output_buffer.write(f"{'=' * 72}{Style.RESET_ALL}\n\n")

    try:
        # Scan each port SEQUENTIALLY
        for idx, p in enumerate(port_list, 1):
            try:
                # Progress update
                if progress_tracker:
                    progress_tracker.update(target_id, tgt, "scanning", port=p, current=idx, total=len(port_list))

                # Perform the scan (output will be captured via thread-local)
                scan_port(sc, p)
                time.sleep(PACE)

            except Exception as e:
                output_buffer.write(f"\n{Fore.RED}Port {p} error: {e}{Style.RESET_ALL}\n")

        output_buffer.write(f"\n{Fore.GREEN}{'=' * 72}\n")
        output_buffer.write(f"COMPLETED: {tgt}\n")
        output_buffer.write(f"{'=' * 72}{Style.RESET_ALL}\n\n")

        # Final completion message
        if progress_tracker:
            progress_tracker.update(target_id, tgt, "complete", total=len(port_list))

        return output_buffer.getvalue()

    except Exception as e:
        if progress_tracker:
            progress_tracker.update(target_id, tgt, "error", total=len(port_list))
        return f"\n{Fore.RED}[FATAL ERROR] Scan failed for {tgt}: {e}{Style.RESET_ALL}\n"
    finally:
        # Clean up thread-local output file
        if hasattr(_thread_local, 'output_file'):
            delattr(_thread_local, 'output_file')

def run_interactive_mode(args):
    """
    Run EVA in interactive mode: collect multiple targets, scan concurrently, display organized results.
    """
    # Collect targets
    targets = collect_targets_interactive()

    if not targets:
        print(Fore.RED + "\nNo targets to scan. Exiting." + Style.RESET_ALL)
        sys.exit(0)

    # Show summary
    print(f"\n{Fore.CYAN}{'=' * 72}")
    print(f"Starting concurrent scan of {len(targets)} target(s)")
    print(f"{'=' * 72}{Style.RESET_ALL}\n")

    for idx, (tgt, ports) in enumerate(targets, 1):
        print(f"  {idx}. {tgt} → {ports}")

    # Check dependencies for all ports
    all_ports = set()
    for _, port_spec in targets:
        try:
            all_ports.update(expand(port_spec))
        except:
            pass
    check_dependencies(sorted(all_ports), args)

    # Run scans concurrently
    output_lock = Lock()
    total_targets = len(targets)
    results = {}  # Store results in order

    print(f"\n{Fore.CYAN}{'=' * 72}")
    print(f"STARTING CONCURRENT SCANS - Live Progress")
    print(f"{'=' * 72}{Style.RESET_ALL}")

    # Create progress tracker
    progress_tracker = ProgressTracker(total_targets)

    # Print initial newline to create space for the progress display
    print()

    # Render thread to update display
    def render_loop():
        while progress_tracker.active:
            progress_tracker.render()
            time.sleep(0.1)  # Update 10 times per second

    render_thread = threading.Thread(target=render_loop, daemon=True)
    render_thread.start()

    try:
        with ThreadPoolExecutor(max_workers=total_targets) as executor:
            # Submit all tasks with target IDs
            future_to_idx = {
                executor.submit(scan_target, tgt, ports, args, output_lock, idx + 1, total_targets, progress_tracker): idx
                for idx, (tgt, ports) in enumerate(targets)
            }

            # Wait for all scans to complete and collect results
            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                try:
                    result = future.result()
                    results[idx] = result
                except Exception as e:
                    results[idx] = f"\n{Fore.RED}[ERROR] Target #{idx + 1} failed: {e}{Style.RESET_ALL}\n"
    finally:
        # Stop the progress tracker
        progress_tracker.stop()
        time.sleep(0.2)  # Let render thread finish

    # Display all results organized by input order
    print(f"\n\n{Fore.CYAN}{'=' * 72}")
    print("SCAN RESULTS (in order of input)")
    print(f"{'=' * 72}{Style.RESET_ALL}\n")

    for idx in sorted(results.keys()):
        print(results[idx])

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
