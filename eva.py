#!/usr/bin/env python3
# ─────────────────────────────────────────────────────────────
#  Author :  Ryan Kucher
#  Version:  8.3
#  Date   :  2025-08-11
# ─────────────────────────────────────────────────────────────
"""
EVA Scanner v8.3 — Sequential, banner-style network scanner with live output.

Highlights
----------
• Human-friendly errors and guidance (no log files, no stack traces by default).
• Live, colorized streaming of command output with clear section headers.
• Fast-path TLS: if the port number contains "443" anywhere (e.g., 443, 1443, 4433, 10443),
  run testssl immediately and skip nmap for speed.
• Smarter TLS trigger in generic flow (uses THIS port's service line only; skips reverse-ssl, IKE).
• Web visibility helper: if site is reachable, auto-open in Firefox (unless --no-firefox)
  and print robots.txt contents, opening it too if present.
• SNMP: still runs even if netcat reports closed; nmap SNMP + snmp-check (public/private).
• IKE: only port 500 runs the ike-scan trilogy; port 4500 stays generic.
• testssl has NO wrapper timeout and will run to completion.

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
import threading
import time
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum
from http import HTTPStatus
from io import StringIO

# ───────── 3rd-party
import requests
import urllib3
from colorama import Fore, Style, init
from tqdm import tqdm

# ───────── init
init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ───────── thread-safe stdout for parallel scanning
_thread_local = threading.local()
_original_stdout = sys.stdout


class ThreadSafeStdout:
    """
    Stdout wrapper that routes writes to thread-local buffers when in parallel mode.
    Each thread can set its own buffer via _thread_local.buffer, and all writes
    will go there instead of the global stdout.
    """
    def write(self, text):
        buffer = getattr(_thread_local, 'buffer', None)
        if buffer is not None:
            buffer.write(text)
        else:
            _original_stdout.write(text)

    def flush(self):
        buffer = getattr(_thread_local, 'buffer', None)
        if buffer is not None:
            buffer.flush()
        else:
            _original_stdout.flush()

    def __getattr__(self, name):
        # Forward all other attributes to original stdout
        return getattr(_original_stdout, name)


# ───────── constants / tuning
CMD_TOUT, CURL_TOUT = 180, 15          # generic timeouts (NOT used for testssl)
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
    """Validate IPv4 address format (0-255 per octet)."""
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", a):
        return False
    try:
        return all(0 <= int(octet) <= 255 for octet in a.split('.'))
    except ValueError:
        return False

def resolve(h: str) -> str:
    return socket.gethostbyname(h)

def require_root():
    if os.geteuid() != 0:
        print(Fore.RED + "This tool needs root privileges. Re-run with sudo or as root." + Style.RESET_ALL)
        sys.exit(1)

# ───────── console formatting helpers
def banner(color, text: str):
    bar = color + "=" * 72 + Style.RESET_ALL
    print("\n" + bar)
    print(color + text + Style.RESET_ALL)
    print(bar)

def show_cmd(cmd):
    print(Fore.LIGHTBLUE_EX + "      Command: " + " ".join(cmd) + Style.RESET_ALL)

def ok(msg: str):
    print("      " + Fore.GREEN + msg + Style.RESET_ALL)

def warn(msg: str):
    print("      " + Fore.YELLOW + msg + Style.RESET_ALL)

def err(msg: str):
    print("      " + Fore.RED + msg + Style.RESET_ALL)

# ───────── ASCII art banner
def print_banner():
    """Display EVA ASCII art banner with cyberpunk styling."""
    banner_art = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║     {Fore.RED}███████╗{Fore.CYAN}╗   ╗{Fore.RED}███████╗        {Fore.YELLOW}External Vulnerability Assessment{Fore.CYAN}      ║
║     {Fore.RED}██╔════╝{Fore.CYAN}╚╗ ╔╝{Fore.RED}██╔══██╗       {Fore.WHITE}Intelligent Network Security Scanner{Fore.CYAN}      ║
║     {Fore.RED}█████╗  {Fore.CYAN} ╚╦╝ {Fore.RED}███████║                                              {Fore.CYAN}║
║     {Fore.RED}██╔══╝  {Fore.CYAN} ╔╩╗ {Fore.RED}██╔══██║       {Fore.GREEN}» {Fore.WHITE}Version 8.3{Fore.CYAN}                              ║
║     {Fore.RED}███████╗{Fore.CYAN}╔╝ ╚╗{Fore.RED}██║  ██║       {Fore.GREEN}» {Fore.WHITE}Author: Ryan Kucher{Fore.CYAN}                      ║
║     {Fore.RED}╚══════╝{Fore.CYAN}╝   ╚{Fore.RED}╚═╝  ╚═╝       {Fore.GREEN}» {Fore.WHITE}Pentesting & Security Research{Fore.CYAN}           ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner_art)
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.WHITE}Authorized Use Only{Style.RESET_ALL} - {Fore.CYAN}Live Vulnerability Assessment Initiated{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─' * 79}{Style.RESET_ALL}\n")

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

# ───────── command runners
def run_live(cmd, desc, timeout=CMD_TOUT) -> str:
    """
    Execute a command, streaming stdout live with nice formatting.
    Returns the complete (lowercased) output for programmatic checks.

    timeout=None -> run without any time limit.
    """
    banner(Fore.YELLOW, f"▶ {desc} (live)")
    show_cmd(cmd)
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
                print("      " + line)
                buf.append(line)
                if timeout is not None and (time.time() - start) > timeout:
                    p.kill()
                    err("[TIMEOUT] The command took too long and was stopped.")
                    warn("Tip: Re-run with --debug or run the command manually to investigate.")
                    break
            p.wait()
            if p.returncode == 0:
                ok("SUCCESS ✓")
            else:
                err(f"FAILED (exit code {p.returncode}).")
                tail = "\n".join(buf[-10:])
                if tail.strip():
                    warn("Last lines from the tool for context:")
                    for ln in tail.splitlines():
                        print("         " + ln)
                warn("Tip: Re-run with --debug to see more detail, or run the command manually.")
            return "\n".join(buf).lower()
    except FileNotFoundError:
        err(f"Cannot run '{cmd[0]}' because it was not found.")
        print("         " + f"Install suggestion: sudo apt-get install {cmd[0]}")
    except PermissionError:
        err(f"Permission denied when executing '{cmd[0]}'.")
        print("         " + "Tip: Ensure the file is executable (chmod +x) or run with sudo/root.")
    except Exception as e:
        err(f"Unexpected problem while running the command: {e}")
        warn("Tip: Re-run with --debug for additional diagnostics.")
    return ""

def run_testssl(args: list[str], desc: str) -> str:
    """
    Wrapper around testssl so the scan never crashes nor prints noisy errors
    if the binary is not present. **No timeout enforced**.
    """
    if TESTSSL_BIN is None:
        warn("Skipping testssl: binary not found on this system.")
        return ""
    full_cmd = [TESTSSL_BIN, *args]
    return run_live(full_cmd, desc, timeout=None)  # no timeout

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
    """Expand port specification (e.g., '80,443,8000-8888') into sorted list.

    Validates that all ports are in valid range (1-65535).
    Raises ValueError if any port is out of bounds.
    """
    out = set()
    for seg in spec.split(","):
        seg = seg.strip()
        if "-" in seg:
            lo, hi = map(int, seg.split("-", 1))
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                raise ValueError(f"Port range {lo}-{hi} out of bounds (valid: 1-65535)")
            if lo > hi:
                raise ValueError(f"Invalid port range {lo}-{hi}: start port must be <= end port")
            out.update(range(lo, hi + 1))
        else:
            port = int(seg)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} out of bounds (valid: 1-65535)")
            out.add(port)
    return sorted(out)

def scan_port_buffered(sc: Scanner, port: int) -> tuple[int, str]:
    """
    Scan a single port and capture all output to a thread-local buffer.
    Returns: (port_number, buffered_output_string)

    Used for parallel scanning to keep output organized.
    Uses thread-local storage to ensure each thread's output is isolated.
    """
    from io import StringIO

    # Create thread-local buffer for this scan
    buffer = StringIO()
    _thread_local.buffer = buffer

    try:
        scan_port(sc, port)
    except Exception as e:
        banner(Fore.RED, f"Port {port} — unexpected error")
        err(f"Something went wrong while scanning port {port}: {e}")
        print("         " + "Tip: Re-run with --debug for more details, or try scanning this port manually.")
    finally:
        # Clean up thread-local buffer
        _thread_local.buffer = None

    return (port, buffer.getvalue())

def cli():
    ap = argparse.ArgumentParser(description="EVA — External Vulnerability Assessment Tool v8.3")
    ap.add_argument("--target", required=True, help="Target IP or hostname to assess")
    ap.add_argument("--ports", required=True, help="Comma list and/or ranges (e.g., 80,443,1-1024)")
    ap.add_argument("--no-ssl", action="store_true", help="Skip all TLS/SSL vulnerability checks")
    ap.add_argument("--no-web", action="store_true", help="Skip HTTP/HTTPS enumeration and browser actions")
    ap.add_argument("--no-firefox", action="store_true", help="Do not launch Firefox for web service verification")
    ap.add_argument("--parallel", type=int, metavar="N", help="Run N port assessments concurrently (stealth mode, buffered output)")
    ap.add_argument("--debug", action="store_true", help="Enable verbose diagnostic output")
    ap.add_argument("--version", action="version", version="EVA Scanner v8.3")
    return ap.parse_args()

def main():
    require_root()
    args = cli()
    setup_log(args.debug)

    # Display ASCII art banner
    print_banner()

    host = strip_proto(args.target)
    try:
        tgt = host if is_ip(host) else resolve(host)
    except Exception as e:
        banner(Fore.RED, "Target resolution error")
        err(f"Could not resolve '{host}': {e}")
        print("         " + "Check DNS/host spelling or try using the raw IP address.")
        sys.exit(1)

    # Display target information
    print(f"{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║{Style.RESET_ALL} {Fore.GREEN}TARGET:{Style.RESET_ALL} {Fore.WHITE}{tgt:<67}{Fore.CYAN}║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║{Style.RESET_ALL} {Fore.GREEN}PORTS: {Style.RESET_ALL} {Fore.WHITE}{args.ports:<67}{Fore.CYAN}║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

    try:
        port_list = expand(args.ports)
    except ValueError as e:
        banner(Fore.RED, "Port specification error")
        err(f"Could not resolve '{host}': {e}")
        print("         " + "Valid formats: 80, 80,443, 1-1024, 22,80,443,8000-8888")
        sys.exit(1)

    check_dependencies(port_list, args)

    sc = Scanner(tgt, args)
    signal.signal(signal.SIGINT, lambda *_: sys.exit("\nInterrupted by user."))

    # Choose scanning mode
    if args.parallel and args.parallel > 1:
        # ─── Parallel mode: assess multiple ports concurrently, display results sequentially ───
        print(f"{Fore.MAGENTA}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}┃{Style.RESET_ALL} {Fore.YELLOW}⚡ STEALTH ASSESSMENT MODE{Style.RESET_ALL} - {Fore.CYAN}{args.parallel} concurrent workers{Style.RESET_ALL}                        {Fore.MAGENTA}┃{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}┃{Style.RESET_ALL} {Fore.WHITE}Results buffered and displayed sequentially after completion{Style.RESET_ALL}             {Fore.MAGENTA}┃{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}┃{Style.RESET_ALL} {Fore.GREEN}Parallel mode reduces IDS/IPS detection signatures{Style.RESET_ALL}                     {Fore.MAGENTA}┃{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{Style.RESET_ALL}")
        print()  # spacing

        # Install thread-safe stdout wrapper for parallel mode
        sys.stdout = ThreadSafeStdout()

        results = {}  # port -> output mapping
        completed_ports = []

        try:
            with ThreadPoolExecutor(max_workers=args.parallel) as executor:
                # Submit all port assessments
                futures = {executor.submit(scan_port_buffered, sc, p): p for p in port_list}

                # Collect results as they complete with live progress updates
                with tqdm(total=len(port_list), desc="Assessing", unit="port",
                         ncols=100, colour="cyan", bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}] {postfix}') as pbar:
                    for future in as_completed(futures):
                        port, output = future.result()
                        results[port] = output
                        completed_ports.append(port)

                        # Update progress bar with last completed port
                        pbar.set_postfix_str(f"✓ Port {port}", refresh=True)
                        pbar.update(1)
        finally:
            # Restore original stdout
            sys.stdout = _original_stdout

        # Show completion summary
        print()
        print(f"{Fore.GREEN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{Style.RESET_ALL}")
        print(f"{Fore.GREEN}┃{Style.RESET_ALL} {Fore.YELLOW}✓ ASSESSMENT COMPLETE{Style.RESET_ALL} - {Fore.WHITE}{len(port_list)} ports analyzed{Style.RESET_ALL}                               {Fore.GREEN}┃{Style.RESET_ALL}")
        print(f"{Fore.GREEN}┃{Style.RESET_ALL} {Fore.CYAN}Completed ports:{Style.RESET_ALL} {Fore.WHITE}{sorted(completed_ports)}{Style.RESET_ALL}", end="")
        print(" " * (75 - len(str(sorted(completed_ports))) - len("Completed ports: ")) + f"{Fore.GREEN}┃{Style.RESET_ALL}")
        print(f"{Fore.GREEN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{Style.RESET_ALL}\n")

        # Display all results in port order
        print(f"{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.CYAN}║{Style.RESET_ALL}             {Fore.YELLOW}VULNERABILITY ASSESSMENT RESULTS{Style.RESET_ALL} {Fore.WHITE}(Sequential Display){Style.RESET_ALL}             {Fore.CYAN}║{Style.RESET_ALL}")
        print(f"{Fore.CYAN}╚═══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        for port in sorted(results.keys()):
            print(results[port], end='')

    else:
        # ─── Sequential mode: traditional live output ───
        print(f"{Fore.CYAN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓{Style.RESET_ALL}")
        print(f"{Fore.CYAN}┃{Style.RESET_ALL} {Fore.YELLOW}▶ SEQUENTIAL ASSESSMENT MODE{Style.RESET_ALL} - {Fore.WHITE}Live output enabled{Style.RESET_ALL}                       {Fore.CYAN}┃{Style.RESET_ALL}")
        print(f"{Fore.CYAN}┃{Style.RESET_ALL} {Fore.GREEN}Real-time streaming results with immediate feedback{Style.RESET_ALL}                       {Fore.CYAN}┃{Style.RESET_ALL}")
        print(f"{Fore.CYAN}┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{Style.RESET_ALL}\n")
        for p in tqdm(port_list, desc="Assessing", unit="port", ncols=80, colour="cyan"):
            try:
                scan_port(sc, p)
            except Exception as e:
                banner(Fore.RED, f"Port {p} — Assessment Error")
                err(f"Something went wrong while assessing port {p}: {e}")
                print("         " + "Tip: Re-run with --debug for more details, or try assessing this port manually.")
            time.sleep(PACE)

    # Final completion banner
    print()
    print(f"{Fore.GREEN}╔═══════════════════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.GREEN}║{Style.RESET_ALL}                                                                               {Fore.GREEN}║{Style.RESET_ALL}")
    print(f"{Fore.GREEN}║{Style.RESET_ALL}               {Fore.YELLOW}✓ VULNERABILITY ASSESSMENT COMPLETE{Style.RESET_ALL}                        {Fore.GREEN}║{Style.RESET_ALL}")
    print(f"{Fore.GREEN}║{Style.RESET_ALL}                                                                               {Fore.GREEN}║{Style.RESET_ALL}")
    print(f"{Fore.GREEN}║{Style.RESET_ALL}         {Fore.CYAN}Thank you for using EVA - External Vulnerability Assessment{Style.RESET_ALL}       {Fore.GREEN}║{Style.RESET_ALL}")
    print(f"{Fore.GREEN}║{Style.RESET_ALL}                   {Fore.WHITE}Stay secure, stay vigilant{Style.RESET_ALL}                               {Fore.GREEN}║{Style.RESET_ALL}")
    print(f"{Fore.GREEN}║{Style.RESET_ALL}                                                                               {Fore.GREEN}║{Style.RESET_ALL}")
    print(f"{Fore.GREEN}╚═══════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")

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
