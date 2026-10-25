#!/usr/bin/env python3
"""
NEST-X Toolkit
==============

One desktop workspace for three cyber-learning tools:

    1. Port Scanner
    2. Password Strength Checker
    3. Random Password Generator

Everything runs locally. No network traffic is sent anywhere except the
port checks you explicitly start against a host you are allowed to test.

Requirements
------------
Python 3.8+ with tkinter (included with the standard Windows installer).

Run
---
    python nestx_launcher.py

Use this toolkit only for education and authorised testing.
"""

from __future__ import annotations

import math
import os
import queue
import secrets
import socket
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, ttk
from tkinter import font as tkfont


APP_NAME = "NEST-X Toolkit"
APP_VERSION = "2.0"


# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
BG = "#081120"
SIDEBAR = "#0b1728"
CARD = "#0f2137"
CARD_ALT = "#122943"
CARD_SOFT = "#0c2030"
BORDER = "#1d3a56"
TEXT = "#e8f3ff"
MUTED = "#8ba3bd"
ACCENT = "#2ee6c8"
ACCENT_SOFT = "#0d3038"
BLUE = "#5cc8ff"
GREEN = "#34d399"
AMBER = "#fbbf24"
ORANGE = "#fb923c"
DANGER = "#f87171"
FONT = "Segoe UI"
MONO = "Consolas"

# ---------------------------------------------------------------------------
# Port scanner data
# ---------------------------------------------------------------------------
PORT_PRESETS = {
    "Common ports": (
        "21,22,23,25,53,69,80,110,111,135,139,143,161,389,443,445,465,"
        "587,636,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,"
        "8443,27017"
    ),
    "Web servers": "80,443,8000,8008,8080,8088,8443,8888",
    "Remote access": "22,23,3389,5900,5985,5986",
    "Databases": "1433,1521,3306,5432,6379,9042,9200,27017",
    "Top 20": (
        "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,"
        "3306,3389,5900,8080"
    ),
    "Custom": "",
}

PORT_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc",
    137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 162: "snmptrap", 179: "bgp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 500: "isakmp", 514: "syslog", 515: "lpd",
    587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1080: "socks", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl",
    2181: "zookeeper", 2375: "docker", 2376: "docker-tls", 3000: "dev-server",
    3306: "mysql", 3389: "rdp", 4444: "metasploit", 5000: "dev-server",
    5432: "postgresql", 5555: "adb", 5601: "kibana", 5672: "amqp",
    5900: "vnc", 5985: "winrm-http", 5986: "winrm-https",
    6379: "redis", 6443: "kubernetes", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9042: "cassandra", 9090: "prometheus", 9200: "elasticsearch",
    9300: "elasticsearch", 10000: "webmin", 11211: "memcached",
    27017: "mongodb", 27018: "mongodb", 50000: "db2",
}

PORT_RISKS = {
    20: "File transfer data channel; check exposure.",
    21: "Plain-text FTP; credentials can be captured.",
    22: "Remote shell service; use keys and restrict access.",
    23: "Telnet sends everything in plain text.",
    25: "Mail service; open relays can be abused.",
    53: "DNS may be abused for amplification attacks.",
    69: "TFTP has no authentication.",
    80: "Unencrypted web traffic; check for a redirect.",
    110: "POP3 may expose credentials in plain text.",
    111: "RPC port mapper reveals available services.",
    135: "Windows RPC is a common attack surface.",
    139: "NetBIOS is a target for SMB-based attacks.",
    143: "IMAP may lack encryption by default.",
    161: "SNMP often uses default community strings.",
    389: "LDAP may expose directory information.",
    443: "Encrypted web traffic; verify the certificate.",
    445: "SMB has a high ransomware and lateral-movement risk.",
    465: "Encrypted mail submission.",
    500: "VPN service; keep it patched.",
    514: "Syslog can leak infrastructure details.",
    587: "Mail submission; secure authentication is essential.",
    631: "Print service; check whether it should be public.",
    636: "Encrypted LDAP directory service.",
    993: "Encrypted IMAP.",
    995: "Encrypted POP3.",
    1080: "Proxy service can expose internal networks.",
    1433: "Microsoft SQL Server; avoid default credentials.",
    1521: "Oracle database; restrict network access.",
    1723: "Legacy VPN protocol.",
    2049: "NFS shares can expose files if misconfigured.",
    2181: "ZooKeeper may expose configuration data.",
    2375: "Docker API without TLS is extremely risky.",
    2376: "Docker API with TLS; verify access controls.",
    3000: "Development service; usually should not be public.",
    3306: "MySQL is often left with default credentials.",
    3389: "RDP is a common brute-force target.",
    4444: "Often used by exploitation tools; verify the owner.",
    5432: "PostgreSQL; restrict network access.",
    5555: "Android debug bridge can allow device access.",
    5672: "Message broker; require authentication.",
    5900: "VNC is often unsecured or weakly protected.",
    5985: "WinRM over HTTP; credentials may need protection.",
    5986: "WinRM over HTTPS; verify certificates.",
    6379: "Redis is frequently exposed without authentication.",
    6443: "Kubernetes API; enforce strong authentication.",
    8000: "Alternative HTTP service; review what it exposes.",
    8080: "Proxy or admin service; check access controls.",
    8443: "Alternative HTTPS service.",
    8888: "Alternative HTTP service.",
    9000: "Admin or application service; restrict access.",
    9200: "Elasticsearch often exposes data without auth.",
    11211: "Memcached can leak cached data.",
    27017: "MongoDB may be exposed without authentication.",
}


def parse_ports(text: str) -> list[int]:
    """Parse values such as '22, 80, 8000-8100' into sorted unique ports."""
    ports: set[int] = set()
    cleaned = (text or "").strip()
    if not cleaned:
        raise ValueError("Enter at least one port or port range.")

    for chunk in re.split(r"[,;\s]+", cleaned):
        if not chunk:
            continue
        if "-" in chunk:
            parts = chunk.split("-", 1)
            if not (parts[0].isdigit() and parts[1].isdigit()):
                raise ValueError(f"'{chunk}' is not a valid port range.")
            start, end = sorted((int(parts[0]), int(parts[1])))
            if start < 1 or end > 65535:
                raise ValueError("Ports must be between 1 and 65535.")
            ports.update(range(start, end + 1))
        elif chunk.isdigit():
            port = int(chunk)
            if not 1 <= port <= 65535:
                raise ValueError("Ports must be between 1 and 65535.")
            ports.add(port)
        else:
            raise ValueError(f"'{chunk}' is not a valid port or range.")

    if not ports:
        raise ValueError("Enter at least one port.")
    if len(ports) > 4096:
        raise ValueError("Please scan 4096 ports or fewer at a time.")
    return sorted(ports)


def lookup_service(port: int) -> str:
    service = PORT_SERVICES.get(port)
    if service:
        return service
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def lookup_risk(port: int) -> str:
    return PORT_RISKS.get(port, "Review whether this service needs to be exposed.")


def human_size(num: int) -> str:
    value = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{num} B"


# ---------------------------------------------------------------------------
# Password data and helpers
# ---------------------------------------------------------------------------
COMMON_PASSWORDS = {
    "password", "password1", "password123", "123456", "12345678",
    "123456789", "1234567890", "qwerty", "qwerty123", "abc123",
    "letmein", "welcome", "admin", "admin123", "iloveyou", "monkey",
    "dragon", "football", "baseball", "sunshine", "princess",
    "master", "shadow", "superman", "michael", "login", "passw0rd",
    "hello", "freedom", "whatever", "trustno1", "starwars", "123123",
    "654321", "111111", "000000", "qazwsx", "zaq12wsx", "1q2w3e4r",
    "password!", "p@ssw0rd", "changeme", "secret", "root", "toor",
}

PASSWORD_CHECKS = [
    "At least 8 characters",
    "12+ characters for extra strength",
    "Contains lowercase letters",
    "Contains uppercase letters",
    "Contains a number",
    "Contains a special character",
    "Not a common password",
    "No simple sequences or repeats",
]

STRENGTH_COLORS = {
    "No password": MUTED,
    "Very weak": DANGER,
    "Weak": ORANGE,
    "Moderate": AMBER,
    "Strong": GREEN,
    "Very strong": ACCENT,
    "Exceptional": ACCENT,
}


def _has_simple_sequence(password: str) -> bool:
    if re.search(r"(.)\1{2,}", password):
        return True
    lowered = password.lower()
    sequences = (
        "0123456789", "9876543210",
        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
        "qwertyuiop", "poiuytrewq",
        "asdfghjkl", "lkjhgfdsa",
        "zxcvbnm", "mnbvcxz",
    )
    return any(seq[i:i + 3] in lowered for seq in sequences for i in range(len(seq) - 2))


def analyze_password(password: str) -> dict:
    """Return score, rating, entropy, checks and improvement suggestions."""
    password = password or ""
    if not password:
        return {
            "score": 0,
            "rating": "No password",
            "color": MUTED,
            "entropy": 0.0,
            "length": 0,
            "classes": 0,
            "checks": [False] * len(PASSWORD_CHECKS),
            "suggestions": ["Enter a password to see live feedback."],
            "empty": True,
        }

    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    classes = sum((has_lower, has_upper, has_digit, has_symbol))
    is_common = password.lower() in COMMON_PASSWORDS
    has_sequence = _has_simple_sequence(password)

    pool = 0
    pool += 26 if has_lower else 0
    pool += 26 if has_upper else 0
    pool += 10 if has_digit else 0
    pool += 32 if has_symbol else 0
    entropy = length * math.log2(pool) if pool else 0.0
    if is_common:
        entropy = min(entropy, 24.0)
    elif has_sequence:
        entropy = min(entropy, max(28.0, entropy * 0.7))

    score = 0
    if length >= 8:
        score += 15
    if length >= 12:
        score += 10
    if length >= 16:
        score += 5
    if has_lower:
        score += 5
    if has_upper:
        score += 10
    if has_digit:
        score += 10
    if has_symbol:
        score += 15
    if not is_common:
        score += 15
    if not has_sequence:
        score += 15
    score = min(score, 100)

    if score < 35:
        rating = "Very weak"
    elif score < 55:
        rating = "Weak"
    elif score < 75:
        rating = "Moderate"
    elif score < 90:
        rating = "Strong"
    else:
        rating = "Very strong"

    checks = [
        length >= 8,
        length >= 12,
        has_lower,
        has_upper,
        has_digit,
        has_symbol,
        not is_common,
        not has_sequence,
    ]

    suggestions: list[str] = []
    if length < 8:
        suggestions.append("Use at least 8 characters (12+ is much better).")
    elif length < 12:
        suggestions.append("Add a few more characters — 12+ is a safer target.")
    if not has_lower:
        suggestions.append("Add lowercase letters.")
    if not has_upper:
        suggestions.append("Add uppercase letters.")
    if not has_digit:
        suggestions.append("Add at least one number.")
    if not has_symbol:
        suggestions.append("Add a special character such as ! @ # $ %.")
    if is_common:
        suggestions.append("Avoid common or previously leaked passwords.")
    if has_sequence:
        suggestions.append("Avoid repeated characters and sequences like abc or 123.")
    if not suggestions:
        suggestions.append("Great password. Keep it unique and store it in a safe place.")

    return {
        "score": score,
        "rating": rating,
        "color": STRENGTH_COLORS[rating],
        "entropy": round(entropy, 1),
        "length": length,
        "classes": classes,
        "checks": checks,
        "suggestions": suggestions,
        "empty": False,
    }


def generate_password(
    length: int,
    use_lower: bool,
    use_upper: bool,
    use_digits: bool,
    use_symbols: bool,
    avoid_ambiguous: bool = False,
) -> tuple[str, int]:
    """Generate a secure password. Returns (password, character pool size)."""
    ambiguous = "O0Il1|`'\"" if avoid_ambiguous else ""

    def clean(chars: str) -> str:
        return "".join(c for c in chars if c not in ambiguous)

    groups: list[str] = []
    if use_lower:
        groups.append(clean(string.ascii_lowercase))
    if use_upper:
        groups.append(clean(string.ascii_uppercase))
    if use_digits:
        groups.append(clean(string.digits))
    if use_symbols:
        groups.append(clean("!@#$%^&*()-_=+[]{};:,.<>?/|~"))

    groups = [g for g in groups if g]
    if not groups:
        raise ValueError("Select at least one character type.")
    if length < len(groups):
        raise ValueError("Password length is too short for the selected character types.")

    pool = "".join(groups)
    # Guarantee at least one character from every selected group.
    chars = [secrets.choice(group) for group in groups]
    chars.extend(secrets.choice(pool) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars), len(pool)


def generator_rating(bits: float) -> str:
    if bits < 36:
        return "Weak"
    if bits < 60:
        return "Reasonable"
    if bits < 90:
        return "Strong"
    if bits < 128:
        return "Very strong"
    return "Exceptional"





# ---------------------------------------------------------------------------
# Small Tk helpers
# ---------------------------------------------------------------------------
def draw_meter(canvas: tk.Canvas, fraction: float, color: str) -> None:
    """Draw a flat progress meter on a Canvas."""
    canvas.delete("all")
    width = max(canvas.winfo_width(), 2)
    height = max(canvas.winfo_height(), 2)
    canvas.create_rectangle(0, 0, width, height, fill=CARD_ALT, outline="")
    if fraction > 0:
        canvas.create_rectangle(
            0, 0, max(2, int(width * min(fraction, 1.0))), height,
            fill=color, outline="",
        )


class ScrollFrame(tk.Frame):
    """A vertically scrollable frame that follows the theme."""

    def __init__(self, parent: tk.Widget):
        super().__init__(parent, bg=BG)
        self.canvas = tk.Canvas(self, bg=BG, highlightthickness=0, bd=0)
        self.scrollbar = ttk.Scrollbar(
            self, orient="vertical", command=self.canvas.yview
        )
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.inner = tk.Frame(self.canvas, bg=BG)
        self._window = self.canvas.create_window(
            (0, 0), window=self.inner, anchor="nw"
        )
        self.inner.bind("<Configure>", self._on_inner_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)
        self.canvas.bind("<Enter>", self._bind_wheel)
        self.canvas.bind("<Leave>", self._unbind_wheel)

    def _on_inner_configure(self, _event=None) -> None:
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event) -> None:
        self.canvas.itemconfigure(self._window, width=event.width)

    def _bind_wheel(self, _event=None) -> None:
        self.canvas.bind_all("<MouseWheel>", self._on_wheel)

    def _unbind_wheel(self, _event=None) -> None:
        self.canvas.unbind_all("<MouseWheel>")

    def _on_wheel(self, event) -> None:
        self.canvas.yview_scroll(int(-event.delta / 120), "units")


# ---------------------------------------------------------------------------
# Main application
# ---------------------------------------------------------------------------
class NestXApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME}  |  v{APP_VERSION}")
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        width = min(1240, max(1140, screen_w - 120))
        height = min(800, max(700, screen_h - 100))
        self.geometry(f"{width}x{height}")
        self.minsize(1140, 700)
        self.configure(bg=BG)

        self.current_page = ""
        self.nav_buttons: dict[str, tk.Button] = {}
        self.page_frames: dict[str, tk.Frame] = {}

        self.scan_queue: queue.Queue = queue.Queue()
        self.scanning = False
        self.stop_scan_event = threading.Event()
        self.scan_results: list[dict] = []
        self.scan_started = 0.0

        self._configure_styles()
        self._build_sidebar()
        self._build_main_area()

        for name, builder in (
            ("home", self._build_home),
            ("scanner", self._build_scanner),
            ("checker", self._build_password_checker),
            ("generator", self._build_password_generator),
            ("about", self._build_about),
        ):
            frame = tk.Frame(self.content, bg=BG)
            frame.grid(row=0, column=0, sticky="nsew")
            self.page_frames[name] = frame
            builder(frame)

        self.show_page("home")
        self.after(250, self._generate_password)

    # ------------------------------------------------------------------
    # Styling and shell
    # ------------------------------------------------------------------
    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Treeview",
            background=CARD_ALT,
            fieldbackground=CARD_ALT,
            foreground=TEXT,
            borderwidth=0,
            rowheight=29,
            font=(FONT, 10),
        )
        style.map(
            "Treeview",
            background=[("selected", "#195066")],
            foreground=[("selected", TEXT)],
        )
        style.configure(
            "Treeview.Heading",
            background=CARD,
            foreground=MUTED,
            relief="flat",
            borderwidth=0,
            font=(FONT, 9, "bold"),
            padding=(8, 7),
        )
        style.map("Treeview.Heading", background=[("active", BORDER)])
        style.configure(
            "Vertical.TScrollbar",
            background=CARD_ALT,
            troughcolor=CARD,
            bordercolor=CARD,
            arrowcolor=MUTED,
            darkcolor=CARD_ALT,
            lightcolor=CARD_ALT,
        )
        style.configure(
            "TCombobox",
            fieldbackground=CARD_ALT,
            background=CARD_ALT,
            foreground=TEXT,
            arrowcolor=ACCENT,
            bordercolor=BORDER,
            lightcolor=BORDER,
            darkcolor=BORDER,
            padding=5,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", CARD_ALT)],
            foreground=[("readonly", TEXT)],
            selectbackground=[("readonly", CARD_ALT)],
            selectforeground=[("readonly", TEXT)],
        )
        self.option_add("*TCombobox*Listbox.background", CARD_ALT)
        self.option_add("*TCombobox*Listbox.foreground", TEXT)
        self.option_add("*TCombobox*Listbox.selectBackground", "#195066")
        self.option_add("*TCombobox*Listbox.selectForeground", TEXT)

    def _build_sidebar(self) -> None:
        sidebar = tk.Frame(self, bg=SIDEBAR, width=250)
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)

        brand = tk.Frame(sidebar, bg=SIDEBAR)
        brand.pack(fill="x", padx=20, pady=(24, 12))

        badge = tk.Canvas(brand, width=48, height=48, bg=SIDEBAR, highlightthickness=0)
        badge.pack(side="left")
        badge.create_polygon(
            24, 3, 43, 10, 43, 25, 24, 45, 5, 25, 5, 10,
            fill=ACCENT_SOFT, outline=ACCENT, width=2,
        )
        badge.create_text(24, 24, text="NX", fill=ACCENT, font=(FONT, 11, "bold"))

        brand_text = tk.Frame(brand, bg=SIDEBAR)
        brand_text.pack(side="left", padx=(12, 0))
        tk.Label(
            brand_text, text="NEST-X", bg=SIDEBAR, fg=TEXT,
            font=(FONT, 17, "bold"),
        ).pack(anchor="w")
        tk.Label(
            brand_text, text="CYBER TOOLKIT", bg=SIDEBAR, fg=MUTED,
            font=(FONT, 7, "bold"),
        ).pack(anchor="w", pady=(1, 0))

        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=20, pady=(8, 14))
        tk.Label(
            sidebar, text="WORKSPACE", bg=SIDEBAR, fg=MUTED,
            font=(FONT, 8, "bold"),
        ).pack(anchor="w", padx=24, pady=(0, 6))

        for key, icon, label in (
            ("home", "⌂", "Dashboard"),
            ("scanner", "◎", "Port Scanner"),
            ("checker", "◈", "Password Checker"),
            ("generator", "✦", "Password Generator"),
            ("about", "ⓘ", "About"),
        ):
            button = tk.Button(
                sidebar,
                text=f"  {icon}    {label}",
                anchor="w",
                bg=SIDEBAR,
                fg=MUTED,
                activebackground=CARD_ALT,
                activeforeground=TEXT,
                bd=0,
                relief="flat",
                font=(FONT, 10, "bold"),
                padx=16,
                pady=10,
                cursor="hand2",
                command=lambda page=key: self.show_page(page),
            )
            button.pack(fill="x", padx=12, pady=1)
            button.bind(
                "<Enter>",
                lambda _e, b=button, k=key: self._hover_nav(b, k, True),
            )
            button.bind(
                "<Leave>",
                lambda _e, b=button, k=key: self._hover_nav(b, k, False),
            )
            self.nav_buttons[key] = button

        spacer = tk.Frame(sidebar, bg=SIDEBAR)
        spacer.pack(fill="both", expand=True)

        safety = tk.Frame(
            sidebar, bg=CARD_SOFT, highlightbackground=BORDER,
            highlightthickness=1,
        )
        safety.pack(fill="x", padx=16, pady=(8, 16))
        tk.Label(
            safety, text="SAFE USE", bg=CARD_SOFT, fg=ACCENT,
            font=(FONT, 8, "bold"),
        ).pack(anchor="w", padx=14, pady=(12, 4))
        tk.Label(
            safety,
            text="Scan only systems you own or have written permission to test.",
            bg=CARD_SOFT,
            fg=MUTED,
            font=(FONT, 8),
            justify="left",
            wraplength=185,
        ).pack(anchor="w", padx=14, pady=(0, 10))
        tk.Label(
            safety, text=f"v{APP_VERSION}   •   local & offline",
            bg=CARD_SOFT, fg="#5f7992", font=(FONT, 8),
        ).pack(anchor="w", padx=14, pady=(0, 12))

    def _build_main_area(self) -> None:
        main = tk.Frame(self, bg=BG)
        main.grid(row=0, column=1, sticky="nsew")
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)
        main.grid_columnconfigure(0, weight=1)

        topbar = tk.Frame(main, bg=BG, height=70)
        topbar.grid(row=0, column=0, sticky="ew", padx=30)
        topbar.grid_propagate(False)
        topbar.grid_columnconfigure(0, weight=1)

        self.page_title = tk.Label(
            topbar, text="Dashboard", bg=BG, fg=TEXT,
            font=(FONT, 15, "bold"),
        )
        self.page_title.grid(row=0, column=0, sticky="w", pady=(18, 0))

        status = tk.Frame(topbar, bg=BG)
        status.grid(row=0, column=1, sticky="e", pady=(18, 0))
        tk.Label(
            status, text="●", bg=BG, fg=ACCENT, font=(FONT, 9),
        ).pack(side="left", padx=(0, 6))
        tk.Label(
            status, text="LOCAL WORKSPACE  •  NO CLOUD",
            bg=BG, fg=MUTED, font=(FONT, 8, "bold"),
        ).pack(side="left")

        separator = tk.Frame(main, bg=BORDER, height=1)
        separator.grid(row=0, column=0, sticky="sew", padx=30)

        self.content = tk.Frame(main, bg=BG)
        self.content.grid(row=1, column=0, sticky="nsew", padx=30, pady=(18, 24))
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

    def _hover_nav(self, button: tk.Button, key: str, entering: bool) -> None:
        if key == self.current_page:
            return
        button.configure(bg=CARD_ALT if entering else SIDEBAR)

    def show_page(self, name: str) -> None:
        if name not in self.page_frames:
            return
        self.current_page = name
        for key, button in self.nav_buttons.items():
            if key == name:
                button.configure(bg=ACCENT_SOFT, fg=ACCENT)
            else:
                button.configure(bg=SIDEBAR, fg=MUTED)
        self.page_frames[name].tkraise()
        titles = {
            "home": "Dashboard",
            "scanner": "Port Scanner",
            "checker": "Password Strength Checker",
            "generator": "Password Generator",
            "about": "About Nest-X",
        }
        self.page_title.configure(text=titles.get(name, "Nest-X"))

    # ------------------------------------------------------------------
    # Reusable widgets
    # ------------------------------------------------------------------
    def _card(self, parent: tk.Widget, **kwargs) -> tk.Frame:
        options = {
            "bg": CARD,
            "highlightbackground": BORDER,
            "highlightthickness": 1,
            "bd": 0,
        }
        options.update(kwargs)
        return tk.Frame(parent, **options)

    def _primary_button(self, parent: tk.Widget, text: str, command, **kwargs) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=ACCENT,
            fg="#042521",
            activebackground="#8af7e8",
            activeforeground="#042521",
            bd=0,
            relief="flat",
            font=(FONT, 10, "bold"),
            padx=16,
            pady=9,
            cursor="hand2",
            **kwargs,
        )

    def _secondary_button(self, parent: tk.Widget, text: str, command, **kwargs) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=CARD_ALT,
            fg=TEXT,
            activebackground=BORDER,
            activeforeground=TEXT,
            bd=0,
            relief="flat",
            font=(FONT, 10, "bold"),
            padx=14,
            pady=9,
            cursor="hand2",
            highlightthickness=1,
            highlightbackground=BORDER,
            **kwargs,
        )

    def _field_label(self, parent: tk.Widget, text: str, bg: str = CARD) -> tk.Label:
        return tk.Label(
            parent, text=text.upper(), bg=bg, fg=MUTED,
            font=(FONT, 8, "bold"),
        )

    def _entry(self, parent: tk.Widget, textvariable=None, **kwargs) -> tk.Entry:
        options = {
            "bg": CARD_ALT,
            "fg": TEXT,
            "insertbackground": ACCENT,
            "relief": "flat",
            "font": (FONT, 10),
            "highlightthickness": 1,
            "highlightbackground": BORDER,
            "highlightcolor": ACCENT,
        }
        options.update(kwargs)
        return tk.Entry(parent, textvariable=textvariable, **options)

    def _checkbutton(self, parent: tk.Widget, text: str, variable, bg: str = CARD, **kwargs) -> tk.Checkbutton:
        return tk.Checkbutton(
            parent,
            text=text,
            variable=variable,
            bg=bg,
            fg=TEXT,
            activebackground=bg,
            activeforeground=TEXT,
            selectcolor=CARD_ALT,
            font=(FONT, 10),
            bd=0,
            highlightthickness=0,
            cursor="hand2",
            **kwargs,
        )

    def _section_heading(self, parent: tk.Widget, kicker: str, title: str, subtitle: str = "") -> None:
        block = tk.Frame(parent, bg=BG)
        block.pack(fill="x", pady=(26, 12))
        tk.Label(
            block, text=kicker.upper(), bg=BG, fg=ACCENT,
            font=(FONT, 8, "bold"),
        ).pack(anchor="w")
        tk.Label(
            block, text=title, bg=BG, fg=TEXT,
            font=(FONT, 20, "bold"),
        ).pack(anchor="w", pady=(4, 0))
        if subtitle:
            tk.Label(
                block, text=subtitle, bg=BG, fg=MUTED,
                font=(FONT, 10), justify="left", wraplength=700,
            ).pack(anchor="w", pady=(4, 0))

    def _page_header(self, parent: tk.Widget, kicker: str, title: str, subtitle: str) -> None:
        header = tk.Frame(parent, bg=BG)
        header.pack(fill="x", pady=(0, 16))
        tk.Label(
            header, text=kicker.upper(), bg=BG, fg=ACCENT,
            font=(FONT, 8, "bold"),
        ).pack(anchor="w")
        tk.Label(
            header, text=title, bg=BG, fg=TEXT,
            font=(FONT, 22, "bold"),
        ).pack(anchor="w", pady=(3, 2))
        tk.Label(
            header, text=subtitle, bg=BG, fg=MUTED,
            font=(FONT, 10), justify="left", wraplength=760,
        ).pack(anchor="w")

    # ------------------------------------------------------------------
    # Home page
    # ------------------------------------------------------------------
    def _build_home(self, parent: tk.Frame) -> None:
        scroll = ScrollFrame(parent)
        scroll.pack(fill="both", expand=True)
        page = scroll.inner

        hero = self._card(page)
        hero.pack(fill="x", pady=(2, 4))

        left = tk.Frame(hero, bg=CARD)
        left.pack(side="left", fill="both", expand=True, padx=(28, 18), pady=26)

        tk.Label(
            left, text="  CYBER LEARNING WORKSPACE  ",
            bg=ACCENT_SOFT, fg=ACCENT, font=(FONT, 8, "bold"),
        ).pack(anchor="w", pady=(0, 12))

        title_row = tk.Frame(left, bg=CARD)
        title_row.pack(anchor="w")
        tk.Label(
            title_row, text="Welcome to ", bg=CARD, fg=TEXT,
            font=(FONT, 30, "bold"),
        ).pack(side="left")
        tk.Label(
            title_row, text="Nest-X", bg=CARD, fg=ACCENT,
            font=(FONT, 30, "bold"),
        ).pack(side="left")

        tk.Label(
            left,
            text=(
                "Explore simple and helpful tools made for cyber learners "
                "and enthusiasts."
            ),
            bg=CARD,
            fg=MUTED,
            font=(FONT, 11),
            justify="left",
            wraplength=470,
        ).pack(anchor="w", pady=(7, 18))

        actions = tk.Frame(left, bg=CARD)
        actions.pack(anchor="w")
        self._primary_button(
            actions, "Open Port Scanner  →",
            lambda: self.show_page("scanner"),
        ).pack(side="left", padx=(0, 10))
        self._secondary_button(
            actions, "About the toolkit",
            lambda: self.show_page("about"),
        ).pack(side="left")

        stats = tk.Frame(left, bg=CARD)
        stats.pack(anchor="w", pady=(24, 0))
        for number, caption in (("3", "tools in one app"), ("100%", "local & offline"), ("1", "simple launcher")):
            column = tk.Frame(stats, bg=CARD)
            column.pack(side="left", padx=(0, 30))
            tk.Label(
                column, text=number, bg=CARD, fg=TEXT,
                font=(FONT, 17, "bold"),
            ).pack(anchor="w")
            tk.Label(
                column, text=caption, bg=CARD, fg=MUTED,
                font=(FONT, 8),
            ).pack(anchor="w")

        terminal = tk.Frame(
            hero, bg=CARD_SOFT, width=280,
            highlightbackground=BORDER, highlightthickness=1,
        )
        # Reserve space for the terminal before the expanding text column.
        terminal.pack(side="right", fill="y", padx=(0, 20), pady=20, before=left)
        terminal.pack_propagate(False)

        dots = tk.Frame(terminal, bg=CARD_SOFT)
        dots.pack(fill="x", padx=14, pady=(12, 0))
        for color in ("#f87171", "#fbbf24", "#34d399"):
            tk.Label(
                dots, text="●", bg=CARD_SOFT, fg=color, font=(FONT, 8),
            ).pack(side="left", padx=(0, 3))
        tk.Label(
            dots, text="nestx_launcher.py", bg=CARD_SOFT, fg=MUTED,
            font=(MONO, 8),
        ).pack(side="right")

        code = tk.Frame(terminal, bg=CARD_SOFT)
        code.pack(fill="both", expand=True, padx=16, pady=(14, 10))
        tk.Label(
            code, text="$ python nestx_launcher.py", bg=CARD_SOFT,
            fg=ACCENT, font=(MONO, 9, "bold"),
        ).pack(anchor="w", pady=(0, 10))
        for tool in (
            "Port Scanner",
            "Password Checker",
            "Password Generator",
        ):
            row = tk.Frame(code, bg=CARD_SOFT)
            row.pack(anchor="w", pady=1)
            tk.Label(
                row, text="✓", bg=CARD_SOFT, fg=GREEN, font=(MONO, 9),
            ).pack(side="left", padx=(0, 6))
            tk.Label(
                row, text=tool, bg=CARD_SOFT, fg=TEXT, font=(MONO, 9),
            ).pack(side="left")
            tk.Label(
                row, text="ready", bg=CARD_SOFT, fg=MUTED, font=(MONO, 8),
            ).pack(side="right", padx=(18, 0))
        tk.Label(
            code, text="Toolkit ready. Choose a tool →", bg=CARD_SOFT,
            fg=BLUE, font=(MONO, 8),
        ).pack(anchor="w", pady=(12, 0))

        self._section_heading(
            page,
            "The toolkit",
            "One workspace, three essentials",
            "Open any tool below. Each one has a guided interface, clear results and no command-line experience required.",
        )

        tools_grid = tk.Frame(page, bg=BG)
        tools_grid.pack(fill="x")
        tools_grid.grid_columnconfigure(0, weight=1, uniform="tool")
        tools_grid.grid_columnconfigure(1, weight=1, uniform="tool")
        tools_grid.grid_columnconfigure(2, weight=1, uniform="tool")

        self._tool_card(
            tools_grid, 0, 0,
            icon="◎", accent=ACCENT, soft=ACCENT_SOFT,
            title="Port Scanner",
            description=(
                "Check open ports safely and learn how services such as SSH, "
                "HTTP, SMB and RDP are exposed on a network."
            ),
            page="scanner",
            tag="NETWORK BASICS",
        )
        self._tool_card(
            tools_grid, 0, 1,
            icon="◈", accent=BLUE, soft="#0e2b44",
            title="Password Strength Checker",
            description=(
                "Understand why a password is weak or strong. Get a live score, "
                "entropy estimate and practical suggestions."
            ),
            page="checker",
            tag="SECURE HABITS",
        )
        self._tool_card(
            tools_grid, 0, 2,
            icon="✦", accent=AMBER, soft="#352b10",
            title="Random Password Generator",
            description=(
                "Create strong, unique passwords instantly with Python's "
                "cryptographically secure secrets module."
            ),
            page="generator",
            tag="SECURE BY DESIGN",
        )

        tip = self._card(page)
        tip.pack(fill="x", pady=(18, 4))
        tk.Label(
            tip, text="ⓘ", bg=CARD, fg=ACCENT, font=(FONT, 14),
        ).pack(side="left", padx=(18, 10), pady=14)
        tk.Label(
            tip,
            text=(
                "Privacy first: your passwords and network scans run entirely "
                "on this computer. Nothing is uploaded or stored."
            ),
            bg=CARD, fg=MUTED, font=(FONT, 9), justify="left",
            wraplength=520,
        ).pack(side="left", pady=14)
        tk.Label(
            tip, text="EDUCATIONAL USE ONLY", bg=CARD, fg=AMBER,
            font=(FONT, 8, "bold"),
        ).pack(side="right", padx=18, pady=14)

    def _tool_card(
        self, parent: tk.Widget, row: int, column: int, *,
        icon: str, accent: str, soft: str, title: str,
        description: str, page: str, tag: str,
    ) -> None:
        card = self._card(parent)
        card.grid(
            row=row, column=column, sticky="nsew",
            padx=(0, 8) if column == 0 else ((5, 5) if column == 1 else (8, 0)),
            pady=(0, 8) if row == 0 else (8, 0),
        )
        inner = tk.Frame(card, bg=CARD)
        inner.pack(fill="both", expand=True, padx=20, pady=18)

        top = tk.Frame(inner, bg=CARD)
        top.pack(fill="x")
        tk.Label(
            top, text=icon, bg=soft, fg=accent,
            font=(FONT, 15, "bold"), padx=10, pady=5,
        ).pack(side="left")
        tk.Label(
            top, text=tag, bg=CARD_ALT, fg=MUTED,
            font=(FONT, 7, "bold"), padx=8, pady=4,
        ).pack(side="right")

        tk.Label(
            inner, text=title, bg=CARD, fg=TEXT,
            font=(FONT, 13, "bold"),
        ).pack(anchor="w", pady=(13, 4))
        tk.Label(
            inner, text=description, bg=CARD, fg=MUTED,
            font=(FONT, 9), justify="left", wraplength=360,
        ).pack(anchor="w")

        open_button = tk.Button(
            inner,
            text="Open tool  →",
            command=lambda target=page: self.show_page(target),
            bg=CARD,
            fg=accent,
            activebackground=CARD,
            activeforeground=accent,
            bd=0,
            relief="flat",
            font=(FONT, 9, "bold"),
            cursor="hand2",
            padx=0,
            pady=0,
        )
        open_button.pack(anchor="w", pady=(12, 0))

    # ------------------------------------------------------------------
    # Port scanner page
    # ------------------------------------------------------------------
    def _build_scanner(self, parent: tk.Frame) -> None:
        self._page_header(
            parent,
            "Network basics · tool 01",
            "Port Scanner",
            "Check which TCP services are reachable on a host. Results include the service name and a short risk note for each port.",
        )

        controls = self._card(parent)
        controls.pack(fill="x", pady=(0, 14))
        inner = tk.Frame(controls, bg=CARD)
        inner.pack(fill="x", padx=20, pady=16)

        top = tk.Frame(inner, bg=CARD)
        top.pack(fill="x")
        top.grid_columnconfigure(0, weight=1)

        target_group = tk.Frame(top, bg=CARD)
        target_group.grid(row=0, column=0, sticky="ew", padx=(0, 12))
        self._field_label(target_group, "Target host or IP").pack(anchor="w")
        self.target_var = tk.StringVar(value="127.0.0.1")
        self.target_entry = self._entry(target_group, self.target_var)
        self.target_entry.pack(fill="x", pady=(4, 0), ipady=6)

        preset_group = tk.Frame(top, bg=CARD)
        preset_group.grid(row=0, column=1, sticky="w", padx=(0, 12))
        self._field_label(preset_group, "Preset").pack(anchor="w")
        self.preset_var = tk.StringVar(value="Common ports")
        self.preset_combo = ttk.Combobox(
            preset_group,
            textvariable=self.preset_var,
            values=list(PORT_PRESETS.keys()),
            state="readonly",
            width=17,
            font=(FONT, 10),
        )
        self.preset_combo.pack(pady=(4, 0), ipady=4)
        self.preset_combo.bind("<<ComboboxSelected>>", self._apply_port_preset)

        timeout_group = tk.Frame(top, bg=CARD)
        timeout_group.grid(row=0, column=2, sticky="w", padx=(0, 12))
        self._field_label(timeout_group, "Timeout (s)").pack(anchor="w")
        self.timeout_var = tk.StringVar(value="0.5")
        self.timeout_spin = tk.Spinbox(
            timeout_group,
            from_=0.1,
            to=5.0,
            increment=0.1,
            textvariable=self.timeout_var,
            width=6,
            bg=CARD_ALT,
            fg=TEXT,
            insertbackground=ACCENT,
            buttonbackground=CARD_ALT,
            relief="flat",
            font=(FONT, 10),
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=ACCENT,
        )
        self.timeout_spin.pack(pady=(4, 0), ipady=5)

        buttons = tk.Frame(top, bg=CARD)
        buttons.grid(row=0, column=3, sticky="sew", padx=(4, 0))
        self.scan_button = self._primary_button(
            buttons, "Start scan", self._start_scan,
        )
        self.scan_button.pack(side="left")
        self.stop_button = self._secondary_button(
            buttons, "Stop", self._stop_scan, state=tk.DISABLED,
        )
        self.stop_button.pack(side="left", padx=(7, 0))

        ports_row = tk.Frame(inner, bg=CARD)
        ports_row.pack(fill="x", pady=(13, 0))
        ports_text = tk.Frame(ports_row, bg=CARD)
        ports_text.pack(fill="x")
        self._field_label(ports_text, "Ports  ·  format: 22, 80, 443, 8000-8100").pack(anchor="w")
        self.ports_var = tk.StringVar(value=PORT_PRESETS["Common ports"])
        self.ports_entry = self._entry(ports_text, self.ports_var, font=(MONO, 10))
        self.ports_entry.pack(fill="x", pady=(4, 0), ipady=6)

        status_row = tk.Frame(inner, bg=CARD)
        status_row.pack(fill="x", pady=(10, 0))
        self.show_closed_var = tk.BooleanVar(value=False)
        self._checkbutton(
            status_row,
            "Show closed ports",
            self.show_closed_var,
            command=self._render_scan_results,
        ).pack(side="right")
        self.scan_hint = tk.Label(
            status_row,
            text="Only scan hosts you own or have explicit permission to test.",
            bg=CARD,
            fg=MUTED,
            font=(FONT, 8),
        )
        self.scan_hint.pack(side="left")

        self.scan_progress = tk.Canvas(
            inner, height=7, bg=CARD_ALT, highlightthickness=0, bd=0,
        )
        self.scan_progress.pack(fill="x", pady=(12, 0))
        self.scan_progress.bind("<Configure>", lambda _e: self._draw_scan_progress())

        self.scan_status = tk.Label(
            inner,
            text="Ready. Choose a preset or enter your own ports.",
            bg=CARD,
            fg=MUTED,
            font=(FONT, 9),
        )
        self.scan_status.pack(anchor="w", pady=(7, 0))

        self._scan_progress_fraction = 0.0
        self._scan_total = 0

        results = self._card(parent)
        results.pack(fill="both", expand=True)
        results_inner = tk.Frame(results, bg=CARD)
        results_inner.pack(fill="both", expand=True, padx=18, pady=14)

        results_head = tk.Frame(results_inner, bg=CARD)
        results_head.pack(fill="x", pady=(0, 10))
        tk.Label(
            results_head, text="Scan results", bg=CARD, fg=TEXT,
            font=(FONT, 12, "bold"),
        ).pack(side="left")

        counts = tk.Frame(results_head, bg=CARD)
        counts.pack(side="right")
        self.scan_open_label = tk.Label(
            counts, text="● 0 OPEN", bg=CARD, fg=GREEN,
            font=(FONT, 8, "bold"),
        )
        self.scan_open_label.pack(side="left", padx=(0, 14))
        self.scan_closed_label = tk.Label(
            counts, text="● 0 CLOSED", bg=CARD, fg=MUTED,
            font=(FONT, 8, "bold"),
        )
        self.scan_closed_label.pack(side="left", padx=(0, 14))
        self.scan_total_label = tk.Label(
            counts, text="0 PORTS", bg=CARD, fg=MUTED,
            font=(FONT, 8, "bold"),
        )
        self.scan_total_label.pack(side="left")

        tree_wrap = tk.Frame(results_inner, bg=CARD_ALT)
        tree_wrap.pack(fill="both", expand=True)

        columns = ("port", "service", "state", "risk")
        self.scan_tree = ttk.Treeview(
            tree_wrap,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        self.scan_tree.heading("port", text="PORT")
        self.scan_tree.heading("service", text="SERVICE")
        self.scan_tree.heading("state", text="STATE")
        self.scan_tree.heading("risk", text="RISK NOTE")
        self.scan_tree.column("port", width=75, anchor="center", stretch=False)
        self.scan_tree.column("service", width=125, anchor="w", stretch=False)
        self.scan_tree.column("state", width=85, anchor="center", stretch=False)
        self.scan_tree.column("risk", width=430, anchor="w", stretch=True)
        self.scan_tree.tag_configure("open", foreground=ACCENT)
        self.scan_tree.tag_configure("closed", foreground=MUTED)

        scrollbar = ttk.Scrollbar(
            tree_wrap, orient="vertical", command=self.scan_tree.yview,
        )
        self.scan_tree.configure(yscrollcommand=scrollbar.set)
        self.scan_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.scan_empty = tk.Label(
            tree_wrap,
            text="Run a scan to see ports and services here.",
            bg=CARD_ALT,
            fg=MUTED,
            font=(FONT, 10),
            justify="center",
        )
        self.scan_empty.place(relx=0.5, rely=0.5, anchor="center")

    def _apply_port_preset(self, _event=None) -> None:
        preset = self.preset_var.get()
        if preset in PORT_PRESETS and PORT_PRESETS[preset]:
            self.ports_var.set(PORT_PRESETS[preset])
        elif preset == "Custom":
            self.ports_entry.focus_set()

    def _draw_scan_progress(self) -> None:
        if hasattr(self, "scan_progress"):
            draw_meter(
                self.scan_progress, self._scan_progress_fraction, ACCENT,
            )

    def _set_scan_progress(self, fraction: float) -> None:
        self._scan_progress_fraction = max(0.0, min(1.0, fraction))
        self._draw_scan_progress()

    def _start_scan(self) -> None:
        if self.scanning:
            return
        host = self.target_var.get().strip()
        if not host:
            messagebox.showwarning("Target required", "Enter a host name or IP address to scan.")
            return
        try:
            ports = parse_ports(self.ports_var.get())
        except ValueError as exc:
            messagebox.showerror("Invalid ports", str(exc))
            return
        try:
            timeout = float(self.timeout_var.get())
        except ValueError:
            timeout = 0.5
        timeout = max(0.1, min(5.0, timeout))

        self.scan_results.clear()
        self._scan_total = len(ports)
        self.scan_started = time.perf_counter()
        self.stop_scan_event.clear()
        self.scanning = True
        self._scan_host = host
        self._render_scan_results()
        self.scan_empty.configure(text="Scanning — results will appear here...")
        self.scan_empty.place(relx=0.5, rely=0.5, anchor="center")
        self._set_scan_progress(0.0)
        self._update_scan_counts()
        self.scan_status.configure(
            text=f"Resolving {host} and scanning {len(ports)} port(s)...",
            fg=MUTED,
        )
        self.scan_button.configure(state=tk.DISABLED, cursor="arrow")
        self.stop_button.configure(state=tk.NORMAL, cursor="hand2")

        threading.Thread(
            target=self._scan_worker,
            args=(host, ports, timeout),
            daemon=True,
        ).start()
        self.after(80, self._poll_scan_queue)

    def _scan_worker(self, host: str, ports: list[int], timeout: float) -> None:
        try:
            ip_address = socket.gethostbyname(host)
        except socket.gaierror as exc:
            self.scan_queue.put(("error", f"Could not resolve '{host}'. {exc}"))
            return
        self.scan_queue.put(("resolved", ip_address))

        workers = min(64, max(1, len(ports)))
        try:
            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(self._probe_port, ip_address, port, timeout): port
                    for port in ports
                }
                for future in as_completed(futures):
                    if self.stop_scan_event.is_set():
                        for pending in futures:
                            pending.cancel()
                        break
                    try:
                        result = future.result()
                    except Exception as exc:  # pragma: no cover - defensive
                        port = futures[future]
                        result = {
                            "port": port,
                            "service": lookup_service(port),
                            "state": "ERROR",
                            "risk": str(exc),
                            "elapsed": 0.0,
                        }
                    self.scan_queue.put(("result", result))
        except Exception as exc:  # pragma: no cover - defensive
            self.scan_queue.put(("error", f"Scan failed: {exc}"))
            return
        self.scan_queue.put(("done", None))

    @staticmethod
    def _probe_port(ip_address: str, port: int, timeout: float) -> dict:
        started = time.perf_counter()
        state = "CLOSED"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sock.connect_ex((ip_address, port)) == 0:
                state = "OPEN"
        except OSError:
            state = "ERROR"
        finally:
            sock.close()
        return {
            "port": port,
            "service": lookup_service(port),
            "state": state,
            "risk": lookup_risk(port),
            "elapsed": time.perf_counter() - started,
        }

    def _poll_scan_queue(self) -> None:
        finished = False
        failed = False
        try:
            while True:
                kind, payload = self.scan_queue.get_nowait()
                if kind == "resolved":
                    self.scan_status.configure(
                        text=f"Scanning {self._scan_host} ({payload}) • {self._scan_total} ports...",
                        fg=MUTED,
                    )
                elif kind == "result":
                    self.scan_results.append(payload)
                    completed = len(self.scan_results)
                    if self._scan_total:
                        self._set_scan_progress(completed / self._scan_total)
                    self.scan_status.configure(
                        text=(
                            f"Scanning {self._scan_host} • "
                            f"{completed} / {self._scan_total} ports checked"
                        ),
                        fg=MUTED,
                    )
                    self._update_scan_counts()
                    if payload["state"] == "OPEN" or self.show_closed_var.get():
                        self._insert_scan_row(payload)
                elif kind == "error":
                    failed = True
                    self.scan_status.configure(text=payload, fg=DANGER)
                    messagebox.showerror("Scan failed", payload)
                elif kind == "done":
                    finished = True
        except queue.Empty:
            pass

        if finished:
            self._finish_scan()
        elif failed:
            self.scanning = False
            self._reset_scan_buttons()
            self.scan_empty.configure(text="Scan could not be completed. Check the host and try again.")
            self.scan_empty.place(relx=0.5, rely=0.5, anchor="center")
        elif self.scanning:
            self.after(80, self._poll_scan_queue)

    def _insert_scan_row(self, result: dict) -> None:
        state = result["state"]
        tag = "open" if state == "OPEN" else "closed"
        self.scan_tree.insert(
            "", "end",
            values=(
                result["port"],
                result["service"],
                state,
                result["risk"],
            ),
            tags=(tag,),
        )

    def _render_scan_results(self) -> None:
        if not hasattr(self, "scan_tree"):
            return
        for item in self.scan_tree.get_children():
            self.scan_tree.delete(item)
        show_closed = self.show_closed_var.get()
        visible = 0
        for result in sorted(self.scan_results, key=lambda item: item["port"]):
            if result["state"] == "OPEN" or show_closed:
                self._insert_scan_row(result)
                visible += 1
        self._update_scan_counts()
        if self.scanning:
            return
        if visible:
            self.scan_empty.place_forget()
        elif self.scan_results:
            self.scan_empty.configure(
                text=(
                    "No open ports found in this scan.\n"
                    "Tick 'Show closed ports' to review every result."
                )
            )
            self.scan_empty.place(relx=0.5, rely=0.5, anchor="center")
        else:
            self.scan_empty.configure(text="Run a scan to see ports and services here.")
            self.scan_empty.place(relx=0.5, rely=0.5, anchor="center")

    def _update_scan_counts(self) -> None:
        open_count = sum(1 for item in self.scan_results if item["state"] == "OPEN")
        closed_count = sum(1 for item in self.scan_results if item["state"] != "OPEN")
        self.scan_open_label.configure(text=f"● {open_count} OPEN")
        self.scan_closed_label.configure(text=f"● {closed_count} CLOSED")
        self.scan_total_label.configure(text=f"{len(self.scan_results)} PORTS")

    def _finish_scan(self) -> None:
        self.scanning = False
        self._render_scan_results()
        elapsed = time.perf_counter() - self.scan_started
        open_count = sum(1 for item in self.scan_results if item["state"] == "OPEN")
        if self.stop_scan_event.is_set():
            summary = "Scan stopped"
        else:
            summary = "Scan complete"
        self._set_scan_progress(1.0)
        self.scan_status.configure(
            text=(
                f"{summary} • {open_count} open port(s) • "
                f"{len(self.scan_results)} checked in {elapsed:.1f}s"
            ),
            fg=GREEN if open_count else MUTED,
        )
        self._reset_scan_buttons()

    def _reset_scan_buttons(self) -> None:
        self.scan_button.configure(state=tk.NORMAL, cursor="hand2")
        self.stop_button.configure(state=tk.DISABLED, cursor="arrow")

    def _stop_scan(self) -> None:
        if not self.scanning:
            return
        self.stop_scan_event.set()
        self.stop_button.configure(state=tk.DISABLED, cursor="arrow")
        self.scan_status.configure(
            text="Stopping after the active checks finish...", fg=AMBER,
        )

    # ------------------------------------------------------------------
    # Password strength checker page
    # ------------------------------------------------------------------
    def _build_password_checker(self, parent: tk.Frame) -> None:
        self._page_header(
            parent,
            "Secure habits · tool 02",
            "Password Strength Checker",
            "Type a password to see a live score, an entropy estimate and practical suggestions. Nothing is stored or sent anywhere.",
        )

        input_card = self._card(parent)
        input_card.pack(fill="x", pady=(0, 14))
        inner = tk.Frame(input_card, bg=CARD)
        inner.pack(fill="x", padx=20, pady=16)

        label_row = tk.Frame(inner, bg=CARD)
        label_row.pack(fill="x")
        self._field_label(label_row, "Enter a password").pack(side="left")
        tk.Label(
            label_row, text="LIVE ANALYSIS  •  STAYS ON THIS DEVICE",
            bg=CARD, fg=ACCENT, font=(FONT, 7, "bold"),
        ).pack(side="right")

        entry_row = tk.Frame(inner, bg=CARD)
        entry_row.pack(fill="x", pady=(6, 0))
        entry_row.grid_columnconfigure(0, weight=1)
        self.pw_var = tk.StringVar()
        self.pw_entry = self._entry(
            entry_row, self.pw_var, show="*", font=(MONO, 13),
        )
        self.pw_entry.grid(row=0, column=0, sticky="ew", ipady=8)
        self.pw_show_var = tk.BooleanVar(value=False)
        self._checkbutton(
            entry_row, "Show", self.pw_show_var,
            command=self._toggle_password_visibility,
        ).grid(row=0, column=1, sticky="w", padx=(12, 0))
        self.pw_var.trace_add("write", lambda *_args: self._update_password_analysis())

        actions = tk.Frame(inner, bg=CARD)
        actions.pack(fill="x", pady=(10, 0))
        self._primary_button(
            actions, "Analyze password", self._update_password_analysis,
        ).pack(side="left")
        self._secondary_button(
            actions, "Clear", self._clear_password,
        ).pack(side="left", padx=(8, 0))
        tk.Label(
            actions,
            text="Tip: use a unique passphrase for every account.",
            bg=CARD, fg=MUTED, font=(FONT, 8),
        ).pack(side="right")

        results = self._card(parent)
        results.pack(fill="both", expand=True)
        inner = tk.Frame(results, bg=CARD)
        inner.pack(fill="both", expand=True, padx=20, pady=16)

        head = tk.Frame(inner, bg=CARD)
        head.pack(fill="x")
        self.pw_rating_label = tk.Label(
            head, text="No password", bg=CARD, fg=MUTED,
            font=(FONT, 23, "bold"),
        )
        self.pw_rating_label.pack(side="left")
        self.pw_score_label = tk.Label(
            head, text="0 / 100", bg=CARD, fg=MUTED,
            font=(MONO, 13, "bold"),
        )
        self.pw_score_label.pack(side="right")

        self.pw_meter = tk.Canvas(
            inner, height=9, bg=CARD_ALT, highlightthickness=0, bd=0,
        )
        self.pw_meter.pack(fill="x", pady=(10, 16))
        self._pw_meter_fraction = 0.0
        self._pw_meter_color = MUTED
        self.pw_meter.bind("<Configure>", lambda _e: self._draw_password_meter())

        metrics = tk.Frame(inner, bg=CARD)
        metrics.pack(fill="x")
        for index in range(3):
            metrics.grid_columnconfigure(index, weight=1, uniform="metric")
        self.pw_length_value = self._metric_card(metrics, 0, "Length", "0 characters")
        self.pw_entropy_value = self._metric_card(metrics, 1, "Estimated entropy", "0 bits")
        self.pw_classes_value = self._metric_card(metrics, 2, "Character classes", "0 of 4")

        checks_block = tk.Frame(inner, bg=CARD)
        checks_block.pack(fill="x", pady=(16, 0))
        tk.Label(
            checks_block, text="SECURITY CHECKLIST", bg=CARD, fg=MUTED,
            font=(FONT, 8, "bold"),
        ).pack(anchor="w", pady=(0, 6))
        check_grid = tk.Frame(checks_block, bg=CARD)
        check_grid.pack(fill="x")
        check_grid.grid_columnconfigure(0, weight=1, uniform="check")
        check_grid.grid_columnconfigure(1, weight=1, uniform="check")
        self.pw_check_labels: list[tk.Label] = []
        for index, label in enumerate(PASSWORD_CHECKS):
            item = tk.Label(
                check_grid,
                text=f"○  {label}",
                bg=CARD,
                fg=MUTED,
                font=(FONT, 9),
                anchor="w",
            )
            item.grid(
                row=index % 4, column=index // 4,
                sticky="w", pady=3, padx=(0, 16),
            )
            self.pw_check_labels.append(item)

        feedback_block = tk.Frame(inner, bg=CARD)
        feedback_block.pack(fill="both", expand=True, pady=(16, 0))
        tk.Label(
            feedback_block, text="SUGGESTIONS", bg=CARD, fg=MUTED,
            font=(FONT, 8, "bold"),
        ).pack(anchor="w", pady=(0, 6))
        self.pw_feedback_frame = tk.Frame(feedback_block, bg=CARD)
        self.pw_feedback_frame.pack(fill="both", expand=True)

        self._update_password_analysis()

    def _metric_card(self, parent: tk.Widget, column: int, label: str, value: str) -> tk.Label:
        card = tk.Frame(
            parent, bg=CARD_ALT, highlightbackground=BORDER, highlightthickness=1,
        )
        card.grid(
            row=0, column=column, sticky="nsew",
            padx=(0, 8) if column < 2 else (0, 0),
        )
        tk.Label(
            card, text=label.upper(), bg=CARD_ALT, fg=MUTED,
            font=(FONT, 7, "bold"),
        ).pack(anchor="w", padx=12, pady=(9, 2))
        value_label = tk.Label(
            card, text=value, bg=CARD_ALT, fg=TEXT,
            font=(FONT, 12, "bold"),
        )
        value_label.pack(anchor="w", padx=12, pady=(0, 9))
        return value_label

    def _toggle_password_visibility(self) -> None:
        self.pw_entry.configure(show="" if self.pw_show_var.get() else "*")

    def _clear_password(self) -> None:
        self.pw_var.set("")
        self.pw_entry.focus_set()

    def _draw_password_meter(self) -> None:
        if hasattr(self, "pw_meter"):
            draw_meter(
                self.pw_meter, self._pw_meter_fraction, self._pw_meter_color,
            )

    def _update_password_analysis(self) -> None:
        if not hasattr(self, "pw_rating_label"):
            return
        analysis = analyze_password(self.pw_var.get())
        self.pw_rating_label.configure(
            text=analysis["rating"], fg=analysis["color"],
        )
        self.pw_score_label.configure(
            text=f"{analysis['score']} / 100", fg=analysis["color"],
        )
        self._pw_meter_fraction = analysis["score"] / 100.0
        self._pw_meter_color = analysis["color"]
        self._draw_password_meter()

        self.pw_length_value.configure(
            text=f"{analysis['length']} character{'s' if analysis['length'] != 1 else ''}"
        )
        self.pw_entropy_value.configure(
            text=f"{analysis['entropy']:.0f} bits" if not analysis["empty"] else "0 bits"
        )
        self.pw_classes_value.configure(text=f"{analysis['classes']} of 4")

        for label, passed in zip(self.pw_check_labels, analysis["checks"]):
            text = label.cget("text")
            base = text.split("  ", 1)[1] if "  " in text else text
            if analysis["empty"]:
                label.configure(text=f"○  {base}", fg=MUTED)
            elif passed:
                label.configure(text=f"✓  {base}", fg=GREEN)
            else:
                label.configure(text=f"✕  {base}", fg=ORANGE)

        for child in self.pw_feedback_frame.winfo_children():
            child.destroy()
        for suggestion in analysis["suggestions"]:
            color = GREEN if analysis["score"] >= 90 else MUTED
            if analysis["empty"]:
                color = MUTED
            tk.Label(
                self.pw_feedback_frame,
                text=f"•  {suggestion}",
                bg=CARD,
                fg=color,
                font=(FONT, 9),
                justify="left",
                anchor="w",
                wraplength=780,
            ).pack(anchor="w", pady=1)

    # ------------------------------------------------------------------
    # Password generator page
    # ------------------------------------------------------------------
    def _build_password_generator(self, parent: tk.Frame) -> None:
        self._page_header(
            parent,
            "Secure by design · tool 03",
            "Random Password Generator",
            "Create a password with Python's cryptographically secure secrets module. Choose the length and character types you need.",
        )

        body = tk.Frame(parent, bg=BG)
        body.pack(fill="both", expand=True)

        options = self._card(body)
        options.pack(side="left", fill="y", padx=(0, 14))
        inner = tk.Frame(options, bg=CARD)
        inner.pack(fill="both", expand=True, padx=20, pady=18)

        tk.Label(
            inner, text="GENERATOR OPTIONS", bg=CARD, fg=MUTED,
            font=(FONT, 8, "bold"),
        ).pack(anchor="w")

        length_row = tk.Frame(inner, bg=CARD)
        length_row.pack(fill="x", pady=(14, 0))
        tk.Label(
            length_row, text="Length", bg=CARD, fg=TEXT,
            font=(FONT, 10, "bold"),
        ).pack(side="left")
        self.gen_length_label = tk.Label(
            length_row, text="16 characters", bg=CARD, fg=ACCENT,
            font=(MONO, 9, "bold"),
        )
        self.gen_length_label.pack(side="right")

        self.gen_length_var = tk.IntVar(value=16)
        self.gen_scale = tk.Scale(
            inner,
            from_=8,
            to=64,
            orient="horizontal",
            variable=self.gen_length_var,
            command=self._update_generator_length,
            showvalue=False,
            length=300,
            bg=CARD,
            fg=TEXT,
            troughcolor=CARD_ALT,
            activebackground=ACCENT,
            highlightthickness=0,
            bd=0,
            sliderrelief="flat",
            sliderlength=20,
            width=10,
        )
        self.gen_scale.pack(fill="x", pady=(4, 14))

        tk.Label(
            inner, text="CHARACTER TYPES", bg=CARD, fg=MUTED,
            font=(FONT, 8, "bold"),
        ).pack(anchor="w", pady=(0, 5))

        self.gen_lower_var = tk.BooleanVar(value=True)
        self.gen_upper_var = tk.BooleanVar(value=True)
        self.gen_digits_var = tk.BooleanVar(value=True)
        self.gen_symbols_var = tk.BooleanVar(value=True)
        types_grid = tk.Frame(inner, bg=CARD)
        types_grid.pack(fill="x")
        types_grid.grid_columnconfigure(0, weight=1)
        types_grid.grid_columnconfigure(1, weight=1)
        self._checkbutton(types_grid, "Lowercase  a-z", self.gen_lower_var).grid(
            row=0, column=0, sticky="w", pady=2,
        )
        self._checkbutton(types_grid, "Uppercase  A-Z", self.gen_upper_var).grid(
            row=0, column=1, sticky="w", pady=2,
        )
        self._checkbutton(types_grid, "Numbers  0-9", self.gen_digits_var).grid(
            row=1, column=0, sticky="w", pady=2,
        )
        self._checkbutton(types_grid, "Symbols  !@#", self.gen_symbols_var).grid(
            row=1, column=1, sticky="w", pady=2,
        )

        self.gen_avoid_var = tk.BooleanVar(value=False)
        self._checkbutton(
            inner, "Avoid ambiguous characters (O, 0, I, l, 1)",
            self.gen_avoid_var,
        ).pack(anchor="w", pady=(10, 0))

        self._primary_button(
            inner, "Generate new password  →", self._generate_password,
        ).pack(fill="x", pady=(18, 0))

        tk.Label(
            inner,
            text=(
                "Each generated password includes at least one character "
                "from every selected type."
            ),
            bg=CARD, fg=MUTED, font=(FONT, 8), justify="left", wraplength=300,
        ).pack(anchor="w", pady=(12, 0))

        result = self._card(body)
        result.pack(side="left", fill="both", expand=True)
        inner = tk.Frame(result, bg=CARD)
        inner.pack(fill="both", expand=True, padx=22, pady=18)

        top = tk.Frame(inner, bg=CARD)
        top.pack(fill="x")
        tk.Label(
            top, text="GENERATED PASSWORD", bg=CARD, fg=MUTED,
            font=(FONT, 8, "bold"),
        ).pack(side="left")
        self.gen_copy_status = tk.Label(
            top, text="Ready to generate", bg=CARD, fg=MUTED,
            font=(FONT, 8),
        )
        self.gen_copy_status.pack(side="right")

        password_row = tk.Frame(inner, bg=CARD)
        password_row.pack(fill="x", pady=(10, 0))
        password_row.grid_columnconfigure(0, weight=1)
        self.gen_password_var = tk.StringVar()
        self.gen_output = tk.Entry(
            password_row,
            textvariable=self.gen_password_var,
            state="readonly",
            readonlybackground=CARD_ALT,
            fg=ACCENT,
            relief="flat",
            font=(MONO, 15, "bold"),
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=ACCENT,
        )
        self.gen_output.grid(row=0, column=0, sticky="ew", ipady=12)
        self._secondary_button(
            password_row, "Copy", self._copy_generated_password,
        ).grid(row=0, column=1, padx=(10, 0))

        self.gen_meter = tk.Canvas(
            inner, height=9, bg=CARD_ALT, highlightthickness=0, bd=0,
        )
        self.gen_meter.pack(fill="x", pady=(18, 16))
        self._gen_meter_fraction = 0.0
        self._gen_meter_color = MUTED
        self.gen_meter.bind("<Configure>", lambda _e: self._draw_generator_meter())

        metrics = tk.Frame(inner, bg=CARD)
        metrics.pack(fill="x")
        for index in range(3):
            metrics.grid_columnconfigure(index, weight=1, uniform="genmetric")
        self.gen_entropy_value = self._metric_card(metrics, 0, "Entropy", "0 bits")
        self.gen_rating_value = self._metric_card(metrics, 1, "Strength", "—")
        self.gen_pool_value = self._metric_card(metrics, 2, "Character pool", "0")

        tips = tk.Frame(inner, bg=CARD_SOFT, highlightbackground=BORDER, highlightthickness=1)
        tips.pack(fill="x", pady=(18, 0))
        tk.Label(
            tips, text="GOOD TO KNOW", bg=CARD_SOFT, fg=ACCENT,
            font=(FONT, 8, "bold"),
        ).pack(anchor="w", padx=14, pady=(10, 4))
        tk.Label(
            tips,
            text=(
                "•  Generated locally with secrets — designed for security, not just randomness.\n"
                "•  Longer passwords are better. Aim for 16+ characters for important accounts.\n"
                "•  Store passwords in a reputable password manager and never reuse them."
            ),
            bg=CARD_SOFT,
            fg=MUTED,
            font=(FONT, 9),
            justify="left",
            wraplength=380,
        ).pack(anchor="w", padx=14, pady=(0, 12))

    def _update_generator_length(self, _value=None) -> None:
        length = int(float(self.gen_length_var.get()))
        self.gen_length_label.configure(
            text=f"{length} character{'s' if length != 1 else ''}"
        )

    def _generate_password(self) -> None:
        length = int(float(self.gen_length_var.get()))
        try:
            password, pool_size = generate_password(
                length,
                self.gen_lower_var.get(),
                self.gen_upper_var.get(),
                self.gen_digits_var.get(),
                self.gen_symbols_var.get(),
                self.gen_avoid_var.get(),
            )
        except ValueError as exc:
            messagebox.showwarning("Cannot generate password", str(exc))
            return

        self.gen_password_var.set(password)
        bits = length * math.log2(pool_size) if pool_size else 0.0
        rating = generator_rating(bits)
        rating_colors = {
            "Weak": DANGER,
            "Reasonable": AMBER,
            "Strong": GREEN,
            "Very strong": ACCENT,
            "Exceptional": ACCENT,
        }
        color = rating_colors.get(rating, MUTED)
        self.gen_entropy_value.configure(text=f"{bits:.0f} bits")
        self.gen_rating_value.configure(text=rating, fg=color)
        self.gen_pool_value.configure(text=f"{pool_size} chars")
        self.gen_copy_status.configure(text="Ready to copy", fg=MUTED)
        self._gen_meter_fraction = min(bits / 128.0, 1.0)
        self._gen_meter_color = color
        self._draw_generator_meter()

    def _draw_generator_meter(self) -> None:
        if hasattr(self, "gen_meter"):
            draw_meter(
                self.gen_meter, self._gen_meter_fraction, self._gen_meter_color,
            )

    def _copy_generated_password(self) -> None:
        password = self.gen_password_var.get()
        if not password:
            return
        self.clipboard_clear()
        self.clipboard_append(password)
        self.update_idletasks()
        self.gen_copy_status.configure(text="✓ Copied to clipboard", fg=GREEN)
        self.after(
            1800,
            lambda: self.gen_copy_status.configure(
                text="Ready to copy", fg=MUTED,
            ),
        )

    # ------------------------------------------------------------------
    # About page
    # ------------------------------------------------------------------
    def _build_about(self, parent: tk.Frame) -> None:
        scroll = ScrollFrame(parent)
        scroll.pack(fill="both", expand=True)
        page = scroll.inner

        hero = self._card(page)
        hero.pack(fill="x", pady=(2, 4))
        inner = tk.Frame(hero, bg=CARD)
        inner.pack(fill="x", padx=28, pady=26)
        tk.Label(
            inner, text="  ABOUT THE PROJECT  ", bg=ACCENT_SOFT, fg=ACCENT,
            font=(FONT, 8, "bold"),
        ).pack(anchor="w")
        tk.Label(
            inner, text="One toolkit for learning cyber safely.", bg=CARD,
            fg=TEXT, font=(FONT, 24, "bold"),
        ).pack(anchor="w", pady=(10, 8))
        tk.Label(
            inner,
            text=(
                "Nest-X brings three practical cybersecurity exercises into one "
                "friendly desktop workspace. It was built as a student project "
                "for learners, ethical hackers and anyone curious about how "
                "networks, passwords and systems really work."
            ),
            bg=CARD, fg=MUTED, font=(FONT, 10), justify="left", wraplength=780,
        ).pack(anchor="w")
        tk.Label(
            inner,
            text=(
                "No accounts. No cloud. No hidden telemetry. Every tool runs on "
                "your machine and gives you an explanation alongside the result."
            ),
            bg=CARD, fg=MUTED, font=(FONT, 10), justify="left", wraplength=780,
        ).pack(anchor="w", pady=(8, 0))

        self._section_heading(page, "What's inside", "Three focused utilities")
        grid = tk.Frame(page, bg=BG)
        grid.pack(fill="x")
        grid.grid_columnconfigure(0, weight=1, uniform="about")
        grid.grid_columnconfigure(1, weight=1, uniform="about")
        grid.grid_columnconfigure(2, weight=1, uniform="about")
        features = (
            ("◎", ACCENT, ACCENT_SOFT, "Port Scanner",
             "Discover reachable TCP services and learn why exposed ports such as Telnet, SMB and RDP need attention."),
            ("◈", BLUE, "#0e2b44", "Password Strength Checker",
             "See how length, character variety, common patterns and entropy affect password safety."),
            ("✦", AMBER, "#352b10", "Password Generator",
             "Create cryptographically secure passwords with clear controls and instant strength feedback."),
        )
        for index, (icon, accent, soft, title, description) in enumerate(features):
            card = self._card(grid)
            card.grid(
                row=0, column=index, sticky="nsew",
                padx=(0, 8) if index == 0 else ((5, 5) if index == 1 else (8, 0)),
                pady=0,
            )
            inner = tk.Frame(card, bg=CARD)
            inner.pack(fill="both", expand=True, padx=18, pady=16)
            tk.Label(
                inner, text=icon, bg=soft, fg=accent,
                font=(FONT, 14, "bold"), padx=9, pady=4,
            ).pack(anchor="w")
            tk.Label(
                inner, text=title, bg=CARD, fg=TEXT,
                font=(FONT, 12, "bold"),
            ).pack(anchor="w", pady=(10, 3))
            tk.Label(
                inner, text=description, bg=CARD, fg=MUTED,
                font=(FONT, 9), justify="left", wraplength=320,
            ).pack(anchor="w")


        ethics = self._card(page)
        ethics.pack(fill="x", pady=(18, 4))
        inner = tk.Frame(ethics, bg=CARD)
        inner.pack(fill="x", padx=24, pady=18)
        tk.Label(
            inner, text="USE IT RESPONSIBLY", bg=CARD, fg=AMBER,
            font=(FONT, 8, "bold"),
        ).pack(anchor="w")
        tk.Label(
            inner,
            text=(
                "Only scan systems you own or have written permission to test. "
                "Never use these tools to access, damage or disrupt someone else's "
                "device or network. Nest-X is a learning aid, not an attack kit."
            ),
            bg=CARD, fg=MUTED, font=(FONT, 9), justify="left", wraplength=780,
        ).pack(anchor="w", pady=(5, 0))
        tk.Label(
            inner,
            text=f"Nest-X Toolkit v{APP_VERSION}  •  Python + Tkinter  •  2025",
            bg=CARD, fg="#5f7992", font=(FONT, 8),
        ).pack(anchor="w", pady=(10, 0))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main() -> None:
    if os.name == "nt":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    app = NestXApp()
    app.mainloop()


if __name__ == "__main__":
    main()
