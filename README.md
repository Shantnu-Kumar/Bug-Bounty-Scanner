**🔐 Bug Bounty Scanner
**An end-to-end Python reconnaissance and vulnerability reporting tool for authorized bug bounty hunters. No third-party dependencies — runs on pure Python standard library.

⚠️ This tool is for authorized bug bounty targets only. Always ensure you have written permission or an active program scope (e.g. via YesWeHack, HackerOne, Bugcrowd) before scanning any target.


✨ **Features**
PhaseWhat it does🔍 Passive ReconSubdomain enumeration via crt.sh + DNS brute-force of common prefixes🖥️ Port ScanningTCP connect scan across 20 common/risky ports🧪 Vuln Scanning10+ automated vulnerability and misconfiguration checks📄 ReportingAuto-generates .txt, .json, and styled .html reports
Vulnerability Checks Included

Security Headers — HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
Cookie Flags — Missing Secure, HttpOnly, SameSite attributes
SSL/TLS — Certificate expiry, weak protocol support (TLS 1.0/1.1), verification failures
CORS Misconfiguration — Wildcard origin with credentials, overly permissive policies
Clickjacking — Missing X-Frame-Options and frame-ancestors CSP directive
Sensitive File Exposure — .git, .env, phpinfo.php, Swagger/API docs, admin panels, backups
Open Redirect — Common redirect parameter fuzzing
Reflected XSS Indicators — Basic reflection detection on common parameters
Information Disclosure — Version leakage via Server, X-Powered-By, X-Generator headers
Risky Open Services — FTP, Telnet, Redis, MongoDB, Elasticsearch, RDP, SMB, MySQL exposed to internet


**🚀 Quick Start
**Requirements

Python 3.7+
No pip installs needed — uses standard library only

**Output Report
**Executive summary with severity breakdown cards
Detected technologies
Subdomains discovered
Open ports table
Full findings table with evidence and remediation advice


🛠️ Architecture
bug_bounty_scanner.py
├── Data Models         (Finding, ScanResult)
├── Phase 1 – Recon     (crt.sh, DNS brute-force, tech fingerprinting)
├── Phase 2 – Ports     (TCP connect scan, 20 common ports)
├── Phase 3 – Vulns     (VulnScanner class, 10+ checks)
└── Phase 4 – Reports   (TXT / JSON / HTML generators)

📊 Severity Levels
SeverityColorMeaningCRITICAL🔴Immediate risk — data exposure, unauthenticated accessHIGH🟠Significant risk — likely exploitableMEDIUM🟡Moderate risk — requires specific conditionsLOW🟢Minor risk — defense in depth issuesINFO🔵Informational — useful for further manual testing

⚙️ Flags Reference
FlagDefaultDescriptiontarget(required in CLI mode)Target domain to scan--output./bb_reportsDirectory to save reports--skip-portsfalseSkip TCP port scanning--skip-subdomainsfalseSkip subdomain enumeration

⚠️ Legal Disclaimer
This tool is intended exclusively for use on systems you own or have explicit written authorization to test, such as through an active bug bounty program on platforms like:

YesWeHack
HackerOne
Bugcrowd
Intigriti

Unauthorized use of this tool against systems you do not have permission to test may violate laws including the Computer Fraud and Abuse Act (CFAA), UAE Cybercrime Law, and similar legislation in your jurisdiction.
The author assumes no liability for misuse.
