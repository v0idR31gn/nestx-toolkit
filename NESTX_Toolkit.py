#!/usr/bin/env python3
"""
NEST-X : HackOps Toolkit
========================

An all-in-one, menu-driven cybersecurity toolkit for students and
ethical hackers. Everything runs locally on your machine.

Tools included
--------------
1. Port Scanner                 - open TCP ports, service names and risk notes
2. Password Strength Analyzer   - length/complexity scoring with fixes
3. Random Password Generator    - cryptographically secure passwords
4. Metadata Extractor           - EXIF/GPS/timestamps + file hashes (ExifTool)
5. Phishing URL Detector        - offline, heuristic URL risk scoring

Requirements
------------
- Python 3.9+
- ExifTool (only for the Metadata Extractor). Place exiftool.exe next to this
  script, or install ExifTool and add it to PATH.
  Kali Linux : sudo apt install libimage-exiftool-perl
  Windows    : https://exiftool.org/

Safety
------
For educational and authorized security testing only. The metadata tool is
read-only, and the URL detector never opens or visits the URL it analyzes.

Run
---
    python NESTX_Toolkit.py
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import secrets
import shutil
import socket
import string
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

# ============================== CONFIGURATION ==================================

APP_NAME = "NEST-X : HackOps Toolkit"
VERSION = "2.1"

SCRIPT_DIR = Path(__file__).resolve().parent
EXIFTOOL_PATH = SCRIPT_DIR / "exiftool.exe"
METADATA_TIMEOUT = 120
HASH_CHUNK_SIZE = 1024 * 1024
DEFAULT_REPORT_DIR = SCRIPT_DIR / "nestx_reports"

# Make console output robust for metadata containing non-ASCII characters.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# ============================== BANNERS ========================================

NEST_X_BANNER = r"""
 _____________________________________________________________________________
 |                        NEST-X : HackOps Toolkit                            |
 |_____________________________________________________________________________|
 | Description :                                                              |
 |     Nest-X is an all-in-one cyber toolkit built with Python.               |
 |     Designed for students, ethical hackers and cybersecurity enthusiasts,  |
 |     it bundles common learning tasks into one interactive workspace.       |
 |                                                                            |
 | Tools :                                                                    |
 |     1. Port Scanner                 2. Password Strength Analyzer          |
 |     3. Random Password Generator    4. Metadata Extractor (ExifTool)       |
 |     5. Phishing URL Detector                                               |
 |                                                                            |
 | Usage      : For educational and authorized security testing only          |
 | Disclaimer : WARNING - Unauthorized scanning is strictly prohibited        |
 |_____________________________________________________________________________|
"""

PORT_SCANNER_BANNER = r"""
  _______________________________________________________________________________
  |                           PORT SCANNER TOOL                                  |
  |______________________________________________________________________________|
  |   Description : Checks for Open Ports + Services + Risk Notes                |
  |   Usage       : For educational and authorized security testing only         |
  |   Disclaimer  : WARNING - Unauthorized scanning is strictly prohibited       |
  |______________________________________________________________________________|
"""

PASSWORD_BANNER = r"""
  ____________________________________________________________
  |                 PASSWORD STRENGTH ANALYZER                 |
  |____________________________________________________________|
  |       Analyzes length, complexity and patterns to          |
  |       determine password security level. Flags weak or     |
  |       common passwords and suggests fixes.                 |
  |____________________________________________________________|
"""

GENERATOR_BANNER = r"""
  ____________________________________________________________
  |                 PASSWORD GENERATOR TOOL                    |
  |____________________________________________________________|
  |  Creates cryptographically secure random passwords using   |
  |  Python's secrets module. Supports customizable length,    |
  |  character sets and ambiguity handling.                    |
  |____________________________________________________________|
"""

METADATA_BANNER = r"""
  ______________________________________________________________________________
  |                    FILE METADATA EXTRACTOR (EXIFTOOL)                       |
  |______________________________________________________________________________|
  |  Extracts EXIF, IPTC, XMP, GPS, maker notes, timestamps and file system     |
  |  details from a single file, and calculates MD5/SHA-1/SHA-256 hashes.       |
  |  Read-only: the analyzed file is never modified.                            |
  |______________________________________________________________________________|
"""

PHISHING_BANNER = r"""
  ______________________________________________________________________________
  |                        PHISHING URL DETECTOR                                |
  |______________________________________________________________________________|
  |  Static, heuristic-based URL analysis. Checks for IP hosts, @ tricks,       |
  |  punycode, URL shorteners, brand impersonation and other warning signs.     |
  |  The URL is never opened or visited.                                        |
  |______________________________________________________________________________|
"""

# ============================== PORT SCANNER ===================================

DEFAULT_PORTS = [23, 25, 53, 69, 110, 139, 143, 445, 3306, 3389, 5900, 8080]

RISKS = {
    23: "Telnet - Plain text encryption",
    25: "SMTP - Open relay risk",
    53: "DNS - Amplification attack risk",
    69: "TFTP - No authentication risk",
    110: "POP3 - Plaintext credentials risk",
    139: "NetBIOS - SMB attack risk",
    143: "IMAP - Encryption not included",
    445: "SMB - Ransomware / lateral movement risk",
    3306: "MySQL - Default credentials risk",
    3389: "RDP - Brute force attack risk",
    5900: "VNC - Often unsecured",
    8080: "Proxy - Internal network exposure risk",
}

SERVICES = {
    23: "telnet",
    25: "smtp",
    53: "dns",
    69: "tftp",
    110: "pop3",
    139: "netbios",
    143: "imap",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5900: "vnc",
    8080: "http-proxy",
}


def show(banner):
    """Print a banner line by line."""
    for line in banner.splitlines():
        print(line)
        time.sleep(0.01)


def parse_ports(value):
    """Parse '22,80,100-110' into a sorted list of unique ports."""
    ports = []
    for chunk in re.split(r"[,;\s]+", value.strip()):
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                raise ValueError(f"Invalid port range: {chunk}")
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(chunk))

    for port in ports:
        if not 1 <= port <= 65535:
            raise ValueError(f"Port out of range: {port}")

    return sorted(set(ports))


def scan_port(ip, port_list=None, timeout=0.5):
    """Scan the given host for open ports. Returns a list of result rows."""
    port_list = port_list if port_list is not None else DEFAULT_PORTS
    rows = []

    print(f"\nScanning {ip}...\n")
    print(f"{'PORT':<8}  {'STATE':<8}  {'SERVICE':<15}  RISK")
    print("-" * 70)

    for port in port_list:
        try:
            sock = socket.socket()
            sock.settimeout(timeout)
            state = "OPEN" if sock.connect_ex((ip, port)) == 0 else "CLOSED"
            sock.close()
        except OSError:
            state = "ERROR"

        risk = RISKS.get(port, "")
        service = SERVICES.get(port, "?")
        print(f"{port:<8} {state:<8} {service:<15} {risk}")
        rows.append((port, state, service, risk))

    open_ports = [row[0] for row in rows if row[1] == "OPEN"]
    print("-" * 70)
    if open_ports:
        print(f"[+] Open ports: {', '.join(str(p) for p in open_ports)}")
    else:
        print("[*] No open ports found on the scanned list.")
    return rows


def port_scanner_tool():
    """Interactive port scanner."""
    show(PORT_SCANNER_BANNER)
    target = input("\nEnter target IP/Host: ").strip()
    if not target:
        print("[!] No target provided.")
        return

    ports_str = input(
        "Enter ports (comma separated, ranges like 1-1024) or press Enter for default: "
    ).strip()

    if not ports_str:
        scan_port(target)
        return

    try:
        ports = parse_ports(ports_str)
    except ValueError as error:
        print(f"[!] Invalid port list: {error}")
        return

    scan_port(target, ports)


# ============================== PASSWORD STRENGTH =============================

def check_password_strength(password):
    """Check password strength. Returns a result dict and prints the verdict."""
    score = 0
    missing = []

    if len(password) >= 8:
        score += 1
    else:
        missing.append("Minimum 8 characters")

    if any(c.islower() for c in password):
        score += 1
    else:
        missing.append("Include lowercase letter")

    if any(c.isupper() for c in password):
        score += 1
    else:
        missing.append("Include uppercase letter")

    if any(c.isdigit() for c in password):
        score += 1
    else:
        missing.append("Include number")

    if any(c in "!@#$%^&*(),.?\":{}|<>" for c in password):
        score += 1
    else:
        missing.append("Include special character")

    if score == 5:
        message = "\nExcellent - Your password meets recommended security standards."
    elif score >= 3:
        message = (
            "\nPassword strength is moderate. Improvements recommended."
            f"\nMissing: {', '.join(missing)}"
        )
    else:
        message = (
            "\nWeak password. Major improvements needed."
            f"\nMissing: {', '.join(missing)}"
        )

    print(message)

    return {
        "score": score,
        "max_score": 5,
        "feedback": missing,
        "message": message.strip(),
    }


def password_strength_tool():
    """Interactive password strength analyzer."""
    show(PASSWORD_BANNER)
    password = input("\nEnter password to check: ")
    if not password:
        print("[!] No password entered.")
        return
    check_password_strength(password)


# ============================== PASSWORD GENERATOR ============================

SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/|~"


def generate_password(length=14, use_lower=True, use_upper=True,
                      use_digits=True, use_symbols=True):
    """Generate a cryptographically secure password. Returns (password, bits, label)."""
    pool = ""
    if use_lower:
        pool += string.ascii_lowercase
    if use_upper:
        pool += string.ascii_uppercase
    if use_digits:
        pool += string.digits
    if use_symbols:
        pool += SYMBOLS

    if not pool:
        raise ValueError("No character sets selected.")

    password = "".join(secrets.choice(pool) for _ in range(length))
    bits = length * math.log(len(pool), 2)

    if bits < 36:
        strength = "Weak"
    elif bits < 60:
        strength = "Reasonable"
    elif bits < 128:
        strength = "Strong"
    else:
        strength = "Very Strong"

    return password, round(bits, 2), strength


def password_generator_tool():
    """Interactive password generator."""
    show(GENERATOR_BANNER)

    while True:
        try:
            length = int(input("\nEnter password length (min 8): ").strip())
        except ValueError:
            print("[!] Enter a valid number.")
            continue

        if length < 8:
            print("[!] Password length must be at least 8.")
            continue

        pool = ""
        if input("Include lowercase? (y/n): ").strip().lower().startswith("y"):
            pool += string.ascii_lowercase
        if input("Include uppercase? (y/n): ").strip().lower().startswith("y"):
            pool += string.ascii_uppercase
        if input("Include numbers? (y/n): ").strip().lower().startswith("y"):
            pool += string.digits
        if input("Include symbols? (y/n): ").strip().lower().startswith("y"):
            pool += SYMBOLS

        if not pool:
            print("[!] No character sets selected. Try again.\n")
            continue

        password = "".join(secrets.choice(pool) for _ in range(length))
        bits = round(length * math.log(len(pool), 2), 2)

        if bits < 36:
            strength = "Weak"
        elif bits < 60:
            strength = "Reasonable"
        elif bits < 128:
            strength = "Strong"
        else:
            strength = "Very Strong"

        print(f"\nGenerated Password: {password}")
        print(f"Entropy: {bits} bits | Strength: {strength}")

        if input("\nGenerate again? (y/n): ").strip().lower() != "y":
            break

    print("\nExiting Password Generator...\n")


# ============================== METADATA EXTRACTOR =============================

def calculate_hashes(file_path):
    """Calculate MD5, SHA-1 and SHA-256 hashes incrementally."""
    digests = {
        "MD5": hashlib.md5(),
        "SHA1": hashlib.sha1(),
        "SHA256": hashlib.sha256(),
    }

    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(HASH_CHUNK_SIZE), b""):
            for digest in digests.values():
                digest.update(chunk)

    return {name: digest.hexdigest() for name, digest in digests.items()}


def resolve_exiftool():
    """Return the ExifTool executable path, or None when unavailable."""
    if EXIFTOOL_PATH.is_file():
        return str(EXIFTOOL_PATH)
    return shutil.which("exiftool")


def extract_metadata(file_path, exiftool, timeout=METADATA_TIMEOUT):
    """Run ExifTool on a single file and return (metadata, warnings)."""
    command = [
        exiftool,
        "-json",
        "-G1",
        "-a",
        "-s",
        "-ee",
        "-api", "LargeFileSupport=1",
        str(file_path),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        errors="replace",
        timeout=timeout,
        check=False,
        cwd=str(SCRIPT_DIR),
    )

    if not result.stdout.strip():
        message = result.stderr.strip() or "No metadata returned."
        raise RuntimeError(message)

    try:
        records = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError(f"Could not parse ExifTool output: {error}") from error

    if not records or not isinstance(records[0], dict):
        raise RuntimeError("No metadata record found.")

    if result.returncode not in (0, 1, 2):
        raise RuntimeError(
            result.stderr.strip()
            or f"ExifTool exited with code {result.returncode}"
        )

    return records[0], result.stderr.strip() or None


def build_metadata_report(file_path, exiftool, timeout=METADATA_TIMEOUT):
    """Collect file properties, hashes and metadata into a report dict."""
    metadata, warnings = extract_metadata(file_path, exiftool, timeout)
    stat = file_path.stat()

    gps_metadata = {
        key: value
        for key, value in metadata.items()
        if any(term in key.lower() for term in
               ("gps", "latitude", "longitude", "altitude"))
    }

    timestamp_metadata = {
        key: value
        for key, value in metadata.items()
        if any(term in key.lower() for term in ("date", "time", "timestamp"))
    }

    return {
        "tool": f"{APP_NAME} - Metadata Extractor",
        "version": VERSION,
        "analysis_time_utc": datetime.now(timezone.utc).isoformat(),
        "file_information": {
            "name": file_path.name,
            "path": str(file_path.resolve()),
            "extension": file_path.suffix.lower(),
            "size_bytes": stat.st_size,
            "modified_time_utc": datetime.fromtimestamp(
                stat.st_mtime, timezone.utc
            ).isoformat(),
            "hashes": calculate_hashes(file_path),
        },
        "summary": {
            "metadata_field_count": len(metadata),
            "gps_fields_found": len(gps_metadata),
            "gps_data_present": bool(gps_metadata),
        },
        "gps_metadata": gps_metadata,
        "timestamp_metadata": timestamp_metadata,
        "all_metadata": metadata,
        "exiftool_warnings": warnings,
    }


def print_metadata_report(report):
    """Display metadata findings in the terminal."""
    print("\n" + "=" * 68)
    print(f" {report['tool']} v{report['version']}")
    print("=" * 68)

    info = report["file_information"]

    print(f"File       : {info['name']}")
    print(f"Path       : {info['path']}")
    print(f"Extension  : {info['extension'] or '(none)'}")
    print(f"Size       : {info['size_bytes']:,} bytes")

    for name, value in info["hashes"].items():
        print(f"{name:<10} : {value}")

    print(f"\nMetadata fields : {report['summary']['metadata_field_count']}")
    print(f"GPS data present: {report['summary']['gps_data_present']}")

    print("\n" + "-" * 68)
    print("EXTRACTED METADATA")
    print("-" * 68)

    for key, value in report["all_metadata"].items():
        print(f"{key}: {value}")

    if report["exiftool_warnings"]:
        print("\n[!] ExifTool messages:")
        print(report["exiftool_warnings"])


def save_metadata_reports(report, file_path, output_dir=DEFAULT_REPORT_DIR):
    """Save JSON and readable TXT reports. Returns (json_path, txt_path)."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Path-derived suffix reduces filename collisions between same-named files.
    path_id = hashlib.sha256(
        str(file_path.resolve()).encode("utf-8")
    ).hexdigest()[:8]

    base = f"{file_path.name}_{path_id}"
    json_path = output_dir / f"{base}.json"
    txt_path = output_dir / f"{base}.txt"

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)

    with txt_path.open("w", encoding="utf-8") as handle:
        handle.write(f"{report['tool']} v{report['version']}\n")
        handle.write("=" * 68 + "\n\n")

        for section in (
            "file_information",
            "summary",
            "gps_metadata",
            "timestamp_metadata",
            "all_metadata",
        ):
            handle.write(section.replace("_", " ").upper() + "\n")
            handle.write("-" * 68 + "\n")
            handle.write(json.dumps(
                report[section], indent=2, ensure_ascii=False
            ))
            handle.write("\n\n")

        handle.write("EXIFTOOL WARNINGS\n")
        handle.write("-" * 68 + "\n")
        handle.write(report["exiftool_warnings"] or "None\n")

    print("\n[+] Reports saved:")
    print(f"    JSON: {json_path.resolve()}")
    print(f"    TXT : {txt_path.resolve()}")
    return json_path, txt_path


def metadata_extractor_tool():
    """Interactive metadata extractor."""
    show(METADATA_BANNER)
    print("[*] Static, read-only extraction. The file is not modified.\n")

    entered = input("Enter full path to file (or drag & drop): ").strip()
    entered = entered.strip('"').strip("'")

    if not entered:
        print("[!] No file path provided.")
        return

    file_path = Path(entered).expanduser()

    if not file_path.exists():
        print("[!] File not found.")
        return
    if not file_path.is_file():
        print("[!] Please provide a file, not a directory.")
        return

    exiftool = resolve_exiftool()
    if not exiftool:
        print("[!] ExifTool was not found.")
        print("    Place exiftool.exe next to this script or install it in PATH.")
        print("    Kali Linux: sudo apt install libimage-exiftool-perl")
        print("    Windows   : https://exiftool.org/")
        return

    print(f"\n[+] Analyzing: {file_path}")
    print("[+] Extracting metadata...")

    try:
        report = build_metadata_report(file_path, exiftool)
    except subprocess.TimeoutExpired:
        print(f"[!] ExifTool timed out after {METADATA_TIMEOUT} seconds.")
        return
    except (OSError, ValueError, RuntimeError) as error:
        print(f"[!] Analysis failed: {error}")
        return

    print_metadata_report(report)

    if input("\nSave JSON/TXT reports? (y/n): ").strip().lower().startswith("y"):
        try:
            save_metadata_reports(report, file_path)
        except OSError as error:
            print(f"[!] Could not save reports: {error}")

    print("\n[+] Analysis completed.")


# ============================== PHISHING URL DETECTOR =========================

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "rb.gy", "cutt.ly", "shorturl.at", "ow.ly",
    "rebrand.ly", "buff.ly",
}

SUSPICIOUS_WORDS = {
    "login", "signin", "verify", "verification", "account",
    "secure", "update", "password", "wallet", "banking",
    "authenticate", "recover", "confirm", "payment",
    "free-gift", "urgent", "suspended",
}

BRANDS = {
    "paypal", "google", "microsoft", "apple", "amazon",
    "facebook", "instagram", "netflix", "coinbase", "binance",
}


def normalize_url(value):
    """Validate and normalize a URL. Returns (url, parsed_url)."""
    value = value.strip().strip("\"'<>")
    if not value:
        raise ValueError("URL cannot be empty.")

    if any(ord(ch) < 32 or ch.isspace() for ch in value):
        raise ValueError("URL contains whitespace or control characters.")

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "https://" + value

    parsed = urlparse(value)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ValueError("URL does not contain a valid hostname.")

    try:
        _ = parsed.port
    except ValueError:
        raise ValueError("URL contains an invalid port.") from None

    return value, parsed


def analyze_url(raw_url):
    """Run static heuristics on a URL and return a result dict."""
    url, parsed = normalize_url(raw_url)
    host = parsed.hostname.lower().rstrip(".")
    decoded = unquote(url)
    indicators = []
    score = 0

    def flag(points, message):
        nonlocal score
        score += points
        indicators.append(f"+{points}: {message}")

    # 1. IP address used as hostname
    try:
        ipaddress.ip_address(host.strip("[]"))
        flag(25, "Hostname is an IP address")
    except ValueError:
        pass

    # 2. URL user-info can disguise the real destination
    if "@" in parsed.netloc:
        flag(25, "Contains @ in the URL authority")

    # 3. HTTPS is useful but does not guarantee legitimacy
    if parsed.scheme.lower() == "http":
        flag(10, "Uses unencrypted HTTP")

    # 4. Punycode can represent internationalized domain names
    if any(label.startswith("xn--") for label in host.split(".")):
        flag(20, "Contains a punycode hostname label")

    # 5. Excessive subdomains
    labels = host.split(".")
    if len(labels) >= 5:
        flag(15, "Has many hostname labels/subdomains")
    elif len(labels) == 4:
        flag(5, "Has several hostname labels")

    # 6. URL shortener
    if host in SHORTENERS:
        flag(15, "Uses a known URL-shortening service")

    # 7. Suspicious words in hostname/path/query
    searchable = (host + parsed.path + parsed.query).lower()
    found_words = sorted(
        word for word in SUSPICIOUS_WORDS if word in searchable
    )
    if found_words:
        flag(10, "Contains suspicious terms: " + ", ".join(found_words[:8]))

    # 8. Brand name embedded in a subdomain (heuristic only, not ownership proof)
    host_without_www = host.removeprefix("www.")
    subdomain_labels = host_without_www.split(".")[:-1]
    for brand in BRANDS:
        if brand in subdomain_labels:
            flag(20, f"Brand name '{brand}' appears in a subdomain")
            break

    # 9. Excessively long URL
    if len(url) > 200:
        flag(10, "URL is unusually long")
    elif len(url) > 100:
        flag(5, "URL is relatively long")

    # 10. Many hyphens in hostname
    if host.count("-") >= 3:
        flag(10, "Hostname contains many hyphens")

    # 11. Encoded or obfuscated URL content
    if re.search(r"%[0-9a-fA-F]{2}", url):
        flag(5, "Contains percent-encoded characters")
    if "\\" in decoded:
        flag(15, "Contains backslash characters")

    # 12. Unusual hostname syntax
    if ".." in host or host.startswith("-") or host.endswith("-"):
        flag(15, "Hostname has unusual formatting")

    score = min(score, 100)

    if score >= 50:
        verdict = "HIGH RISK"
    elif score >= 25:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOW RISK"

    return {
        "url": url,
        "hostname": host,
        "scheme": parsed.scheme,
        "risk_score": score,
        "verdict": verdict,
        "indicators": indicators,
    }


def print_phishing_report(result):
    """Display a phishing URL analysis report."""
    print("\n" + "-" * 58)
    print("ANALYSIS REPORT")
    print("-" * 58)
    print("URL       :", result["url"])
    print("Hostname  :", result["hostname"])
    print("Scheme    :", result["scheme"])
    print("Risk score:", f"{result['risk_score']}/100")
    print("Verdict   :", result["verdict"])

    print("\nIndicators:")
    if result["indicators"]:
        for item in result["indicators"]:
            print("  [!]", item)
    else:
        print("  No configured heuristic indicators were detected.")

    print("\nNote: This is a heuristic result, not a guarantee.")
    print("A low score does NOT prove that a URL is safe.")
    print("-" * 58)


def phishing_url_tool():
    """Interactive phishing URL detector."""
    show(PHISHING_BANNER)
    print("[*] Static analysis only; the URL will not be opened.\n")

    while True:
        raw_url = input("Enter URL to analyze: ").strip()
        if not raw_url:
            print("[!] No URL provided.")
            break

        try:
            result = analyze_url(raw_url)
        except ValueError as error:
            print(f"[!] {error}")
        else:
            print_phishing_report(result)

        if input("\nAnalyze another URL? (y/n): ").strip().lower() != "y":
            break


# ============================== MAIN MENU ======================================

MENU_ITEMS = [
    ("1", "Port Scanner", port_scanner_tool),
    ("2", "Password Strength Analyzer", password_strength_tool),
    ("3", "Random Password Generator", password_generator_tool),
    ("4", "Metadata Extractor (ExifTool)", metadata_extractor_tool),
    ("5", "Phishing URL Detector", phishing_url_tool),
    ("6", "Exit", None),
]


def main_menu():
    """Show the main menu and dispatch the selected tool."""
    while True:
        show(NEST_X_BANNER)
        print()
        for key, label, _ in MENU_ITEMS:
            print(f"    [{key}] {label}")
        print()

        choice = input("Enter your choice [1-6]: ").strip()

        selected = next(
            (item for item in MENU_ITEMS if item[0] == choice),
            None,
        )

        if selected is None:
            print("\n[!] Invalid choice. Please try again.")
            time.sleep(1)
            continue

        _, _, action = selected

        if action is None:
            print("\nThank you for using NEST-X Toolkit. Goodbye!")
            return

        try:
            action()
        except KeyboardInterrupt:
            print("\n\n[!] Operation cancelled.")
        except Exception as error:  # keep the menu alive on unexpected errors
            print(f"\n[!] Unexpected error: {error}")

        input("\nPress Enter to return to menu...")


def main():
    print(f"\n{APP_NAME} v{VERSION}")
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\nExiting... Goodbye!")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
