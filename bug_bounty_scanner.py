#!/usr/bin/env python3
"""
Bug Bounty Scanner - End-to-End Recon & Reporting Tool
For authorized bug bounty targets only.
Author: Bug Bounty Script
"""

import sys
import os
import re
import json
import socket
import ssl
import time
import datetime
import argparse
import urllib.request
import urllib.error
import urllib.parse
import concurrent.futures
from dataclasses import dataclass, field, asdict
from typing import List, Optional


# ─────────────────────────────────────────────
#  Data Models
# ─────────────────────────────────────────────

@dataclass
class Finding:
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category: str
    title: str
    description: str
    url: str
    evidence: str = ""
    recommendation: str = ""

@dataclass
class ScanResult:
    target: str
    scan_time: str = field(default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    subdomains: List[str] = field(default_factory=list)
    open_ports: List[dict] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    headers: dict = field(default_factory=dict)


# ─────────────────────────────────────────────
#  Helper Utilities
# ─────────────────────────────────────────────

RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"

SEV_COLOR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     RED,
    "MEDIUM":   YELLOW,
    "LOW":      GREEN,
    "INFO":     CYAN,
}

def banner():
    print(f"""{CYAN}{BOLD}
╔══════════════════════════════════════════════════════╗
║          Bug Bounty Scanner — Authorized Use Only    ║ Developed by:
║          End-to-End Recon & Vulnerability Reporter   ║ SHANTNU KUMAR
╚══════════════════════════════════════════════════════╝
{RESET}""")

def log(level: str, msg: str):
    color = SEV_COLOR.get(level, CYAN)
    print(f"[{color}{level}{RESET}] {msg}")

def make_request(url: str, timeout: int = 8) -> Optional[urllib.request.Request]:
    """Send GET request, return (response_obj, body_text) or None on failure."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 BugBountyScanner/1.0 (Authorized)"},
        )
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(50_000).decode("utf-8", errors="replace")
            return resp, body
    except Exception:
        return None, None


# ─────────────────────────────────────────────
#  Phase 1 — Passive Recon
# ─────────────────────────────────────────────

def passive_subdomain_enum(domain: str) -> List[str]:
    """Enumerate subdomains via crt.sh certificate transparency logs."""
    log("INFO", f"Querying crt.sh for subdomains of {domain} ...")
    found = set()

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        _, body = make_request(url, timeout=15)
        if body:
            data = json.loads(body)
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(domain) and sub != domain:
                        found.add(sub)
    except Exception as e:
        log("INFO", f"crt.sh error: {e}")

    # Also check common prefixes via DNS resolution
    common = ["www", "api", "dev", "staging", "test", "admin", "mail",
              "vpn", "portal", "dashboard", "cdn", "static", "assets",
              "login", "auth", "app", "mobile", "beta", "old", "new"]

    def resolve(sub):
        fqdn = f"{sub}.{domain}"
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname(fqdn)
            return fqdn
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(resolve, s): s for s in common}
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if result:
                found.add(result)

    subs = sorted(found)
    log("INFO", f"Found {len(subs)} subdomains")
    for s in subs:
        print(f"   {GREEN}→ {s}{RESET}")
    return subs


def grab_headers(url: str) -> dict:
    """Grab HTTP response headers."""
    resp, _ = make_request(url)
    if resp:
        return dict(resp.headers)
    return {}


def detect_technologies(body: str, headers: dict) -> List[str]:
    """Basic technology fingerprinting from headers + body."""
    techs = []
    checks = {
        "WordPress":    ["wp-content", "wp-includes", "wordpress"],
        "Drupal":       ["drupal", "sites/default/files"],
        "Joomla":       ["joomla", "/components/com_"],
        "Laravel":      ["laravel_session", "laravel"],
        "Django":       ["csrfmiddlewaretoken", "django"],
        "React":        ["react", "__REACT", "data-reactroot"],
        "Angular":      ["ng-version", "angular"],
        "Vue.js":       ["vue.js", "vue.min.js"],
        "jQuery":       ["jquery"],
        "Bootstrap":    ["bootstrap"],
        "Nginx":        ["nginx"],
        "Apache":       ["apache"],
        "PHP":          [".php", "x-powered-by: php"],
        "ASP.NET":      ["asp.net", "x-aspnet-version"],
        "Cloudflare":   ["cf-ray", "cloudflare"],
        "AWS":          ["x-amz", "amazonaws"],
    }
    combined = (body + " " + " ".join(f"{k}: {v}" for k, v in headers.items())).lower()
    for tech, patterns in checks.items():
        if any(p.lower() in combined for p in patterns):
            techs.append(tech)
    return techs


# ─────────────────────────────────────────────
#  Phase 2 — Port Scanning
# ─────────────────────────────────────────────

COMMON_PORTS = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "HTTP-Dev",
    9200: "Elasticsearch",
    27017:"MongoDB",
}

def scan_ports(domain: str) -> List[dict]:
    """TCP connect scan on common ports."""
    log("INFO", f"Scanning common ports on {domain} ...")
    open_ports = []

    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        log("INFO", f"Could not resolve {domain}")
        return []

    def check_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                return {"port": port, "service": COMMON_PORTS.get(port, "Unknown"), "ip": ip}
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = [ex.submit(check_port, p) for p in COMMON_PORTS]
        for f in concurrent.futures.as_completed(futures):
            result = f.result()
            if result:
                open_ports.append(result)
                log("INFO", f"   Open: {result['port']}/tcp ({result['service']}) on {ip}")

    return sorted(open_ports, key=lambda x: x["port"])


# ─────────────────────────────────────────────
#  Phase 3 — Vulnerability Checks
# ─────────────────────────────────────────────

class VulnScanner:
    def __init__(self, base_url: str):
        self.base = base_url.rstrip("/")
        self.findings: List[Finding] = []

    def add(self, severity, category, title, desc, url, evidence="", rec=""):
        self.findings.append(Finding(severity, category, title, desc, url, evidence, rec))
        color = SEV_COLOR.get(severity, CYAN)
        print(f"   {color}[{severity}]{RESET} {title} → {url}")

    # ── Security Headers ──────────────────────────────────────────────
    def check_security_headers(self, headers: dict):
        log("INFO", "Checking security headers ...")
        url = self.base

        required = {
            "Strict-Transport-Security": (
                "MEDIUM", "Missing HSTS Header",
                "HSTS header is not set. Users may be vulnerable to SSL-stripping attacks.",
                "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            ),
            "Content-Security-Policy": (
                "MEDIUM", "Missing CSP Header",
                "Content-Security-Policy is not set, allowing potential XSS attacks.",
                "Implement a strict CSP policy."
            ),
            "X-Frame-Options": (
                "LOW", "Missing X-Frame-Options Header",
                "Page can be embedded in an iframe, enabling clickjacking attacks.",
                "Add: X-Frame-Options: DENY or SAMEORIGIN"
            ),
            "X-Content-Type-Options": (
                "LOW", "Missing X-Content-Type-Options Header",
                "Browser may MIME-sniff responses, enabling content injection.",
                "Add: X-Content-Type-Options: nosniff"
            ),
            "Referrer-Policy": (
                "INFO", "Missing Referrer-Policy Header",
                "Referrer information may leak sensitive data to third parties.",
                "Add: Referrer-Policy: no-referrer-when-downgrade"
            ),
            "Permissions-Policy": (
                "INFO", "Missing Permissions-Policy Header",
                "Browser feature policies are not restricted.",
                "Add Permissions-Policy header to restrict sensitive browser APIs."
            ),
        }

        h_lower = {k.lower(): v for k, v in headers.items()}
        for header, (sev, title, desc, rec) in required.items():
            if header.lower() not in h_lower:
                self.add(sev, "Security Headers", title, desc, url, f"Header '{header}' not present", rec)

        # Check for information-leaking headers
        for leak in ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]:
            val = h_lower.get(leak.lower())
            if val:
                self.add("LOW", "Information Disclosure",
                         f"Version Disclosure via {leak}",
                         f"The header '{leak}: {val}' reveals technology/version info.",
                         url, f"{leak}: {val}",
                         f"Remove or obscure the '{leak}' header in server configuration.")

    # ── Sensitive Files ───────────────────────────────────────────────
    def check_sensitive_files(self):
        log("INFO", "Checking for exposed sensitive files ...")
        sensitive = [
            ("/.git/HEAD",          "CRITICAL", "Exposed .git Directory",
             "The .git directory is publicly accessible, leaking source code.",
             "Block access to .git in your web server configuration."),
            ("/.env",               "CRITICAL", "Exposed .env File",
             ".env file is publicly accessible, potentially leaking API keys and credentials.",
             "Block access to .env files via web server rules."),
            ("/wp-config.php.bak",  "CRITICAL", "WordPress Config Backup Exposed",
             "WordPress config backup may contain DB credentials.",
             "Remove backup files from web root."),
            ("/config.php",         "HIGH", "Config File Exposed",
             "Configuration file is publicly accessible.",
             "Move config files outside web root or restrict access."),
            ("/backup.zip",         "HIGH", "Backup Archive Exposed",
             "Backup archive found; may contain sensitive data.",
             "Remove backup files from web root."),
            ("/phpinfo.php",        "HIGH", "PHPInfo Exposed",
             "phpinfo() page exposes server configuration details.",
             "Remove phpinfo.php from production."),
            ("/server-status",      "MEDIUM", "Apache Server Status Exposed",
             "Apache mod_status page reveals request data.",
             "Restrict /server-status to localhost."),
            ("/robots.txt",         "INFO", "robots.txt Found",
             "robots.txt may reveal hidden paths.",
             "Review robots.txt for sensitive path disclosures."),
            ("/.well-known/security.txt", "INFO", "security.txt Found",
             "Security contact file found.",
             ""),
            ("/crossdomain.xml",    "LOW", "crossdomain.xml Found",
             "Cross-domain policy file found; review for overly permissive rules.",
             "Restrict allowed domains in crossdomain.xml."),
            ("/sitemap.xml",        "INFO", "sitemap.xml Found",
             "Sitemap found; useful for additional endpoint discovery.",
             ""),
            ("/.htaccess",          "LOW", ".htaccess Found",
             ".htaccess file may be readable, revealing server rules.",
             "Ensure .htaccess is not directly accessible."),
            ("/api/swagger.json",   "MEDIUM", "Swagger API Docs Exposed",
             "Swagger/OpenAPI spec exposed, revealing all API endpoints.",
             "Restrict API documentation to authenticated users."),
            ("/api-docs",           "MEDIUM", "API Docs Exposed",
             "API documentation endpoint found.",
             "Restrict access to API documentation in production."),
            ("/graphql",            "INFO", "GraphQL Endpoint Found",
             "GraphQL endpoint discovered; test for introspection and injection.",
             "Disable introspection in production."),
            ("/admin",              "MEDIUM", "Admin Panel Found",
             "Admin panel found; verify it requires strong authentication.",
             "Ensure admin panel is protected and not accessible to the public."),
            ("/login",              "INFO", "Login Page Found",
             "Login page found; test for brute-force protection and default creds.",
             "Implement rate-limiting and MFA on login."),
            ("/console",            "HIGH", "Developer Console Found",
             "Developer/debug console may be accessible.",
             "Disable debug console in production."),
        ]

        def check(path_info):
            path, sev, title, desc, rec = path_info
            url = self.base + path
            resp, body = make_request(url)
            if resp and resp.status < 400 and body:
                evidence = f"HTTP {resp.status} — {len(body)} bytes"
                # Extra validation for .git
                if path == "/.git/HEAD" and "ref:" not in body:
                    return
                self.add(sev, "Sensitive Files", title, desc, url, evidence, rec)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            ex.map(check, sensitive)

    # ── SSL/TLS ───────────────────────────────────────────────────────
    def check_ssl(self, domain: str):
        log("INFO", "Checking SSL/TLS configuration ...")
        url = self.base

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert()

            # Check expiry
            expire_str = cert.get("notAfter", "")
            if expire_str:
                expire = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expire - datetime.datetime.utcnow()).days
                if days_left < 30:
                    self.add("HIGH", "SSL/TLS",
                             f"SSL Certificate Expiring Soon ({days_left} days)",
                             f"The SSL certificate expires on {expire_str}.",
                             url, f"Expiry: {expire_str}",
                             "Renew the SSL certificate immediately.")
                else:
                    log("INFO", f"   SSL certificate valid for {days_left} days")

            # Check weak protocols
            for proto in [ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1] if hasattr(ssl, "PROTOCOL_TLSv1") else []:
                try:
                    weak_ctx = ssl.SSLContext(proto)
                    weak_ctx.check_hostname = False
                    weak_ctx.verify_mode = ssl.CERT_NONE
                    with weak_ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                        s.settimeout(3)
                        s.connect((domain, 443))
                    self.add("HIGH", "SSL/TLS",
                             f"Weak Protocol Supported ({proto})",
                             "Server accepts deprecated TLS 1.0/1.1.",
                             url, f"Protocol accepted: {proto}",
                             "Disable TLS 1.0 and 1.1; use TLS 1.2+ only.")
                except Exception:
                    pass

        except ssl.SSLCertVerificationError:
            self.add("HIGH", "SSL/TLS", "SSL Certificate Verification Failed",
                     "Certificate could not be verified (self-signed or invalid).",
                     url, "SSL verification error",
                     "Install a valid, CA-signed SSL certificate.")
        except Exception as e:
            log("INFO", f"   SSL check skipped: {e}")

    # ── HTTP to HTTPS redirect ────────────────────────────────────────
    def check_http_redirect(self, domain: str):
        log("INFO", "Checking HTTP → HTTPS redirect ...")
        url = f"http://{domain}"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "BugBountyScanner/1.0"})
            urllib.request.urlopen(req, timeout=5)
            # If we get here without redirect exception, HTTP is accessible without redirect
            self.add("MEDIUM", "SSL/TLS",
                     "HTTP Not Redirected to HTTPS",
                     "The site serves content over plain HTTP without redirecting to HTTPS.",
                     url, "HTTP 200 on plain HTTP",
                     "Add a 301 redirect from HTTP to HTTPS.")
        except urllib.error.HTTPError as e:
            if str(e.code).startswith("3"):
                log("INFO", f"   HTTP → HTTPS redirect OK (HTTP {e.code})")
        except Exception:
            pass

    # ── XSS / Injection via Reflection Check ─────────────────────────
    def check_reflection(self):
        log("INFO", "Checking for basic reflection (potential XSS indicators) ...")
        test_params = ["q", "s", "search", "query", "keyword", "id", "name", "page", "url"]
        payload = "<script>xss</script>"
        encoded = urllib.parse.quote(payload)

        for param in test_params:
            url = f"{self.base}?{param}={encoded}"
            _, body = make_request(url)
            if body and payload in body:
                self.add("HIGH", "XSS",
                         f"Potential Reflected XSS in parameter '{param}'",
                         f"The parameter '{param}' reflects the input without sanitization.",
                         url, f"Payload reflected: {payload}",
                         "Sanitize and encode all user inputs before rendering in HTML.")
                break

    # ── Open Redirect ─────────────────────────────────────────────────
    def check_open_redirect(self):
        log("INFO", "Checking for open redirect ...")
        redirect_params = ["redirect", "url", "next", "return", "returnUrl",
                           "goto", "destination", "target", "redir", "continue"]
        evil = "https://evil.example.com"

        for param in redirect_params:
            url = f"{self.base}?{param}={urllib.parse.quote(evil)}"
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "BugBountyScanner/1.0"})
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                urllib.request.urlopen(req, timeout=5, context=ctx)
            except urllib.error.HTTPError as e:
                if str(e.code).startswith("3"):
                    loc = e.headers.get("Location", "")
                    if "evil.example.com" in loc:
                        self.add("HIGH", "Open Redirect",
                                 f"Open Redirect via '{param}' parameter",
                                 "Application redirects to arbitrary external URLs.",
                                 url, f"Location: {loc}",
                                 "Validate redirect URLs against an allowlist.")
            except Exception:
                pass

    # ── Cookie Flags ──────────────────────────────────────────────────
    def check_cookies(self, headers: dict):
        log("INFO", "Checking cookie security flags ...")
        url = self.base
        set_cookie = headers.get("Set-Cookie", "")
        if not set_cookie:
            return

        cookies = set_cookie.split(",")
        for cookie in cookies:
            cookie_low = cookie.lower()
            name = cookie.split("=")[0].strip()

            if "secure" not in cookie_low:
                self.add("MEDIUM", "Cookie Security",
                         f"Cookie '{name}' Missing Secure Flag",
                         "Cookie can be sent over HTTP, enabling interception.",
                         url, f"Set-Cookie: {cookie.strip()}",
                         "Add the 'Secure' flag to all cookies.")

            if "httponly" not in cookie_low:
                self.add("MEDIUM", "Cookie Security",
                         f"Cookie '{name}' Missing HttpOnly Flag",
                         "Cookie is accessible via JavaScript, enabling XSS theft.",
                         url, f"Set-Cookie: {cookie.strip()}",
                         "Add the 'HttpOnly' flag to all sensitive cookies.")

            if "samesite" not in cookie_low:
                self.add("LOW", "Cookie Security",
                         f"Cookie '{name}' Missing SameSite Attribute",
                         "Missing SameSite attribute may allow CSRF attacks.",
                         url, f"Set-Cookie: {cookie.strip()}",
                         "Add SameSite=Strict or SameSite=Lax to cookies.")

    # ── CORS Misconfiguration ─────────────────────────────────────────
    def check_cors(self, headers: dict):
        log("INFO", "Checking CORS configuration ...")
        url = self.base
        acao = headers.get("Access-Control-Allow-Origin", "")
        acac = headers.get("Access-Control-Allow-Credentials", "")

        if acao == "*" and acac.lower() == "true":
            self.add("CRITICAL", "CORS",
                     "CORS Wildcard with Credentials Allowed",
                     "Server allows any origin with credentials, enabling cross-site data theft.",
                     url, f"ACAO: {acao} | ACAC: {acac}",
                     "Never combine 'Access-Control-Allow-Origin: *' with 'Allow-Credentials: true'.")
        elif acao == "*":
            self.add("LOW", "CORS",
                     "CORS Wildcard Origin",
                     "Server allows requests from any origin.",
                     url, f"Access-Control-Allow-Origin: {acao}",
                     "Restrict CORS to trusted origins only.")

    # ── Clickjacking ──────────────────────────────────────────────────
    def check_clickjacking(self, headers: dict, body: str):
        log("INFO", "Checking for clickjacking protection ...")
        url = self.base
        xfo = headers.get("X-Frame-Options", "")
        csp = headers.get("Content-Security-Policy", "")

        has_frame_ancestors = "frame-ancestors" in csp.lower()
        has_xfo = bool(xfo)

        if not has_frame_ancestors and not has_xfo:
            self.add("MEDIUM", "Clickjacking",
                     "Clickjacking Protection Missing",
                     "No X-Frame-Options or CSP frame-ancestors directive found.",
                     url, "Neither X-Frame-Options nor frame-ancestors in CSP",
                     "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.")

    # ── Default / Weak Paths ──────────────────────────────────────────
    def check_exposed_ports_services(self, open_ports: List[dict]):
        log("INFO", "Analyzing open ports for risky services ...")
        risky = {
            21:    ("HIGH", "FTP Exposed", "FTP (port 21) is open. FTP transmits credentials in plaintext.", "Disable FTP; use SFTP instead."),
            23:    ("CRITICAL", "Telnet Exposed", "Telnet (port 23) is open. All traffic is unencrypted.", "Disable Telnet; use SSH."),
            3306:  ("HIGH", "MySQL Exposed to Internet", "MySQL (port 3306) is publicly accessible.", "Firewall MySQL; bind to localhost only."),
            5432:  ("HIGH", "PostgreSQL Exposed", "PostgreSQL (port 5432) is publicly accessible.", "Firewall PostgreSQL."),
            6379:  ("CRITICAL", "Redis Exposed (No Auth)", "Redis (port 6379) is publicly accessible. Often has no auth.", "Firewall Redis; enable requirepass."),
            27017: ("CRITICAL", "MongoDB Exposed", "MongoDB (port 27017) is publicly accessible.", "Firewall MongoDB; enable authentication."),
            9200:  ("HIGH", "Elasticsearch Exposed", "Elasticsearch is publicly accessible.", "Firewall Elasticsearch."),
            3389:  ("HIGH", "RDP Exposed", "RDP (port 3389) is exposed. High risk of brute-force.", "Restrict RDP behind VPN."),
            445:   ("HIGH", "SMB Exposed", "SMB (port 445) is exposed. Risk of ransomware/exploitation.", "Block SMB at firewall."),
        }
        for p in open_ports:
            port = p["port"]
            if port in risky:
                sev, title, desc, rec = risky[port]
                self.add(sev, "Network Exposure",
                         title, desc,
                         f"Port {port} on {p['ip']}",
                         f"Port {port}/tcp open ({p['service']})", rec)

    def run_all(self, domain: str, headers: dict, open_ports: List[dict]) -> List[Finding]:
        _, body = make_request(self.base)
        body = body or ""

        self.check_security_headers(headers)
        self.check_cookies(headers)
        self.check_cors(headers)
        self.check_clickjacking(headers, body)
        self.check_ssl(domain)
        self.check_http_redirect(domain)
        self.check_sensitive_files()
        self.check_reflection()
        self.check_open_redirect()
        self.check_exposed_ports_services(open_ports)
        return self.findings


# ─────────────────────────────────────────────
#  Phase 4 — Report Generation
# ─────────────────────────────────────────────

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def severity_counts(findings: List[Finding]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts

def generate_text_report(result: ScanResult, out_path: str):
    """Write a structured plain-text report."""
    lines = []
    sep = "=" * 70

    lines += [
        sep,
        "  BUG BOUNTY SCAN REPORT",
        sep,
        f"  Target   : {result.target}",
        f"  Scan Date: {result.scan_time}",
        f"  Tool     : Bug Bounty Scanner v1.0 (Authorized Use Only)",
        sep, "",
    ]

    counts = severity_counts(result.findings)
    lines += [
        "EXECUTIVE SUMMARY",
        "-" * 40,
        f"  Total Findings : {len(result.findings)}",
        f"  Critical       : {counts['CRITICAL']}",
        f"  High           : {counts['HIGH']}",
        f"  Medium         : {counts['MEDIUM']}",
        f"  Low            : {counts['LOW']}",
        f"  Informational  : {counts['INFO']}",
        "",
    ]

    if result.technologies:
        lines += ["DETECTED TECHNOLOGIES", "-" * 40]
        for t in result.technologies:
            lines.append(f"  • {t}")
        lines.append("")

    if result.subdomains:
        lines += ["SUBDOMAINS DISCOVERED", "-" * 40]
        for s in result.subdomains:
            lines.append(f"  • {s}")
        lines.append("")

    if result.open_ports:
        lines += ["OPEN PORTS", "-" * 40]
        for p in result.open_ports:
            lines.append(f"  • {p['port']}/tcp  {p['service']:20s}  {p['ip']}")
        lines.append("")

    lines += ["VULNERABILITY FINDINGS", sep]
    sorted_findings = sorted(result.findings, key=lambda f: SEV_ORDER.get(f.severity, 99))

    for i, f in enumerate(sorted_findings, 1):
        lines += [
            f"\n[{i:03d}] [{f.severity}] {f.title}",
            f"      Category   : {f.category}",
            f"      URL        : {f.url}",
            f"      Description: {f.description}",
        ]
        if f.evidence:
            lines.append(f"      Evidence   : {f.evidence}")
        if f.recommendation:
            lines.append(f"      Fix        : {f.recommendation}")

    lines += ["", sep, "END OF REPORT", sep]

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    log("INFO", f"Text report saved → {out_path}")


def generate_json_report(result: ScanResult, out_path: str):
    """Write JSON report."""
    data = {
        "target": result.target,
        "scan_time": result.scan_time,
        "summary": severity_counts(result.findings),
        "technologies": result.technologies,
        "subdomains": result.subdomains,
        "open_ports": result.open_ports,
        "findings": [asdict(f) for f in
                     sorted(result.findings, key=lambda f: SEV_ORDER.get(f.severity, 99))]
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    log("INFO", f"JSON report saved → {out_path}")


def generate_html_report(result: ScanResult, out_path: str):
    """Write a styled HTML report."""
    counts = severity_counts(result.findings)
    sorted_findings = sorted(result.findings, key=lambda f: SEV_ORDER.get(f.severity, 99))

    sev_badge = {
        "CRITICAL": "#c0392b", "HIGH": "#e67e22",
        "MEDIUM":   "#f1c40f", "LOW":  "#27ae60", "INFO": "#2980b9"
    }

    rows = ""
    for i, f in enumerate(sorted_findings, 1):
        color = sev_badge.get(f.severity, "#999")
        rows += f"""
        <tr>
          <td>{i}</td>
          <td><span class="badge" style="background:{color}">{f.severity}</span></td>
          <td>{f.category}</td>
          <td>{f.title}</td>
          <td style="font-size:0.85em">{f.url}</td>
          <td>{f.description}</td>
          <td style="font-size:0.85em;color:#555">{f.evidence}</td>
          <td style="font-size:0.85em;color:#155724">{f.recommendation}</td>
        </tr>"""

    subs_html = "".join(f"<li>{s}</li>" for s in result.subdomains) or "<li>None found</li>"
    ports_html = "".join(
        f"<li><code>{p['port']}/tcp</code> — {p['service']} ({p['ip']})</li>"
        for p in result.open_ports
    ) or "<li>No risky ports found</li>"
    tech_html = "".join(f"<span class='tech'>{t}</span>" for t in result.technologies) or "Unknown"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Bug Bounty Report — {result.target}</title>
<style>
  body {{ font-family: Arial, sans-serif; background: #f4f6f9; color: #222; margin: 0; padding: 20px; }}
  h1 {{ color: #2c3e50; }}
  h2 {{ border-bottom: 2px solid #2c3e50; padding-bottom: 6px; color: #2c3e50; }}
  .meta {{ background: #2c3e50; color: #fff; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
  .meta p {{ margin: 4px 0; }}
  .summary {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }}
  .card {{ background: #fff; border-radius: 8px; padding: 16px 24px; text-align: center; box-shadow: 0 2px 6px rgba(0,0,0,.1); min-width: 100px; }}
  .card .num {{ font-size: 2em; font-weight: bold; }}
  .critical {{ color: #c0392b; }} .high {{ color: #e67e22; }}
  .medium {{ color: #f39c12; }} .low {{ color: #27ae60; }} .info {{ color: #2980b9; }}
  table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 6px rgba(0,0,0,.1); }}
  th {{ background: #2c3e50; color: #fff; padding: 10px; text-align: left; font-size: 0.85em; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #eee; vertical-align: top; font-size: 0.88em; }}
  tr:hover {{ background: #f0f4f8; }}
  .badge {{ color: #fff; padding: 2px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; }}
  .tech {{ background: #3498db; color: #fff; padding: 2px 8px; border-radius: 4px; margin: 2px; display: inline-block; font-size: 0.85em; }}
  ul {{ margin: 6px 0; padding-left: 20px; }}
  .section {{ background: #fff; border-radius: 8px; padding: 16px 20px; margin-bottom: 20px; box-shadow: 0 2px 6px rgba(0,0,0,.1); }}
  .footer {{ text-align: center; color: #888; font-size: 0.8em; margin-top: 30px; }}
</style>
</head>
<body>
<div class="meta">
  <h1>🔐 Bug Bounty Scan Report</h1>
  <p><strong>Target:</strong> {result.target}</p>
  <p><strong>Scan Date:</strong> {result.scan_time}</p>
  <p><strong>Tool:</strong> Bug Bounty Scanner v1.0 — Authorized Use Only</p>
</div>

<h2>Executive Summary</h2>
<div class="summary">
  <div class="card"><div class="num critical">{counts['CRITICAL']}</div><div>Critical</div></div>
  <div class="card"><div class="num high">{counts['HIGH']}</div><div>High</div></div>
  <div class="card"><div class="num medium">{counts['MEDIUM']}</div><div>Medium</div></div>
  <div class="card"><div class="num low">{counts['LOW']}</div><div>Low</div></div>
  <div class="card"><div class="num info">{counts['INFO']}</div><div>Info</div></div>
  <div class="card"><div class="num">{len(result.findings)}</div><div>Total</div></div>
</div>

<div class="section">
  <h2>Technologies Detected</h2>
  {tech_html}
</div>

<div class="section">
  <h2>Subdomains Discovered ({len(result.subdomains)})</h2>
  <ul>{subs_html}</ul>
</div>

<div class="section">
  <h2>Open Ports</h2>
  <ul>{ports_html}</ul>
</div>

<h2>Vulnerability Findings ({len(sorted_findings)})</h2>
<table>
  <tr>
    <th>#</th><th>Severity</th><th>Category</th><th>Title</th>
    <th>URL</th><th>Description</th><th>Evidence</th><th>Recommendation</th>
  </tr>
  {rows}
</table>

<div class="footer">
  Generated by Bug Bounty Scanner v1.0 — For authorized bug bounty programs only.
</div>
</body>
</html>"""

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    log("INFO", f"HTML report saved → {out_path}")


# ─────────────────────────────────────────────
#  Main Orchestrator
# ─────────────────────────────────────────────

def run_scan(target: str, output_dir: str, skip_ports: bool, skip_subdomains: bool):
    banner()

    # Normalize target
    domain = target.replace("https://", "").replace("http://", "").rstrip("/")
    base_url = f"https://{domain}"

    print(f"{BOLD}Target  : {domain}{RESET}")
    print(f"{BOLD}Base URL: {base_url}{RESET}")
    print()

    result = ScanResult(target=domain)
    os.makedirs(output_dir, exist_ok=True)

    # Phase 1 — Passive Recon
    print(f"\n{BOLD}{CYAN}[ Phase 1: Passive Recon ]{RESET}")
    if not skip_subdomains:
        result.subdomains = passive_subdomain_enum(domain)

    # Grab headers + fingerprint
    log("INFO", "Fetching main page headers ...")
    result.headers = grab_headers(base_url)
    _, body = make_request(base_url)
    result.technologies = detect_technologies(body or "", result.headers)
    if result.technologies:
        log("INFO", f"Technologies: {', '.join(result.technologies)}")

    # Phase 2 — Port Scan
    print(f"\n{BOLD}{CYAN}[ Phase 2: Port Scanning ]{RESET}")
    if not skip_ports:
        result.open_ports = scan_ports(domain)
    else:
        log("INFO", "Port scan skipped (--skip-ports)")

    # Phase 3 — Vulnerability Scanning
    print(f"\n{BOLD}{CYAN}[ Phase 3: Vulnerability Scanning ]{RESET}")
    scanner = VulnScanner(base_url)
    result.findings = scanner.run_all(domain, result.headers, result.open_ports)

    # Phase 4 — Reports
    print(f"\n{BOLD}{CYAN}[ Phase 4: Generating Reports ]{RESET}")
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = domain.replace(".", "_")

    txt_path  = os.path.join(output_dir, f"report_{safe_domain}_{ts}.txt")
    json_path = os.path.join(output_dir, f"report_{safe_domain}_{ts}.json")
    html_path = os.path.join(output_dir, f"report_{safe_domain}_{ts}.html")

    generate_text_report(result, txt_path)
    generate_json_report(result, json_path)
    generate_html_report(result, html_path)

    # Console summary
    counts = severity_counts(result.findings)
    print(f"""
{BOLD}{'═'*60}
  SCAN COMPLETE — {domain}
{'═'*60}{RESET}
  {RED+BOLD}Critical : {counts['CRITICAL']}{RESET}
  {RED}High     : {counts['HIGH']}{RESET}
  {YELLOW}Medium   : {counts['MEDIUM']}{RESET}
  {GREEN}Low      : {counts['LOW']}{RESET}
  {CYAN}Info     : {counts['INFO']}{RESET}
  {'─'*40}
  Total    : {len(result.findings)}
{BOLD}{'═'*60}{RESET}
Reports saved in: {output_dir}
""")


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────

def prompt_yes_no(question: str, default: bool = False) -> bool:
    """Ask a yes/no question and return True/False."""
    hint = "[Y/n]" if default else "[y/N]"
    while True:
        answer = input(f"  {question} {hint}: ").strip().lower()
        if answer == "":
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  Please enter 'y' or 'n'.")


def interactive_prompt() -> tuple:
    """Interactively collect all scan options from the user."""
    banner()

    print(f"{BOLD}Welcome to Bug Bounty Scanner — Authorized Use Only{RESET}")
    print(f"{YELLOW}⚠  Only scan targets you have explicit written authorization to test.{RESET}\n")

    # ── Domain ────────────────────────────────────────────────────────
    while True:
        domain = input(f"{BOLD}  Enter target domain (e.g. google.com): {RESET}").strip()
        domain = domain.replace("https://", "").replace("http://", "").rstrip("/")
        if domain:
            break
        print(f"  {RED}Domain cannot be empty. Please try again.{RESET}")

    # ── Authorization confirmation ────────────────────────────────────
    print()
    confirmed = prompt_yes_no(
        f"Do you confirm you are AUTHORIZED to scan '{domain}' (e.g. via YesWeHack / HackerOne)?",
        default=False
    )
    if not confirmed:
        print(f"\n{RED}Scan aborted. Only run this tool on authorized targets.{RESET}\n")
        sys.exit(0)

    # ── Output directory ──────────────────────────────────────────────
    print()
    output_raw = input(f"  {BOLD}Output directory{RESET} [./bb_reports]: ").strip()
    output_dir = output_raw if output_raw else "./bb_reports"

    # ── Options ───────────────────────────────────────────────────────
    print()
    skip_subdomains = not prompt_yes_no("Run subdomain enumeration?", default=True)
    skip_ports      = not prompt_yes_no("Run port scanning?",         default=True)

    print(f"\n{BOLD}{CYAN}Starting scan on: {domain}{RESET}\n")
    time.sleep(1)

    return domain, output_dir, skip_ports, skip_subdomains


def main():
    interactive = len(sys.argv) == 1  # No CLI args → interactive mode

    if interactive:
        domain, output_dir, skip_ports, skip_subdomains = interactive_prompt()
        run_scan(domain, output_dir, skip_ports, skip_subdomains)
    else:
        # Keep CLI mode for scripting / automation
        parser = argparse.ArgumentParser(
            description="Bug Bounty Scanner — Authorized targets only",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python bug_bounty_scanner.py              ← interactive mode (recommended)
  python bug_bounty_scanner.py google.com
  python bug_bounty_scanner.py google.com --output ./reports
  python bug_bounty_scanner.py google.com --skip-ports
  python bug_bounty_scanner.py google.com --skip-subdomains --skip-ports
            """
        )
        parser.add_argument("target", help="Target domain (e.g. google.com)")
        parser.add_argument("--output", default="./bb_reports", help="Output directory for reports")
        parser.add_argument("--skip-ports", action="store_true", help="Skip port scanning")
        parser.add_argument("--skip-subdomains", action="store_true", help="Skip subdomain enumeration")

        args = parser.parse_args()
        run_scan(args.target, args.output, args.skip_ports, args.skip_subdomains)


if __name__ == "__main__":
    main()
