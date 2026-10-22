#!/usr/bin/env python3
"""
VANGUARD — the first and last line of defense for your local machine,
your AI agents, and anything they run. Pure Python stdlib, no deps.

Commands:
  scan      full local threat scan (processes, ports, launch agents, shell, PHP)
  harden    apply defenses (dry-run by default; --yes to apply)
  guard     continuous monitor — alert on new suspicious activity
  ai        defend AI agents (secret leak scan + prompt-injection check + tool policy)
  php       check the local PHP install against known 2026 CVEs
  web       website fortress (audit a site / run the reverse-proxy WAF)
  net       self network audit (listening services)
  repo      supply-chain scan of a GitHub repo or local dir
"""
import argparse
import http.server
import json
import os
import platform
import re
import shutil
import socket
import socketserver
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

VERSION = "1.0.0"
IS_MAC = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"

# ----------------------------------------------------------------------------
# Threat intelligence
# ----------------------------------------------------------------------------

# The October 2026 PHP vulnerability wave (and the deserialization family that
# keeps recurring). `fixed` is the first fixed version per branch.
PHP_CVES = [
    {"cve": "CVE-2026-14355", "cvss": "high",
     "what": "ext/openssl memory corruption in openssl_encrypt() with AES-WRAP-PAD",
     "fixed": {"8.2": "8.2.31", "8.3": "8.3.31", "8.4": "8.4.21", "8.5": "8.5.6"}},
    {"cve": "CVE-2026-7568", "cvss": "high",
     "what": "metaphone() buffer overflow via a string > 2^31 bytes",
     "fixed": {"8.2": "8.2.31", "8.3": "8.3.31", "8.4": "8.4.21", "8.5": "8.5.6"}},
    {"cve": "CVE-2026-33942", "cvss": "critical",
     "what": "Saloon PHP library insecure deserialization (unserialize() in AccessTokenAuthenticator)",
     "fixed": {"lib": "4.0.0"}},
    {"cve": "CVE-2026-78529", "cvss": "critical",
     "what": "Unauthenticated PHP Object Injection (Alliance <= 3.11)",
     "fixed": {"lib": "3.12"}},
    {"cve": "CVE-2024-4577", "cvss": "critical",
     "what": "PHP-CGI argument injection (Windows CGI mode) — RCE",
     "fixed": {"8.1": "8.1.29", "8.2": "8.2.20", "8.3": "8.3.8"}},
]

# Processes that are almost never legitimate.
SUSPICIOUS_PROCESS = [
    r"xmrig", r"kworkerds", r"kdevtmpfsi", r"kinsing", r"masscan", r"mimikatz",
    r"pwnkit", r"keylog", r"cryptomin", r"cpuminer", r"ethminer", r"trojan",
    r"payload", r"meterpreter", r"beacon\.exe", r"ncat", r"netcat", r"reverseshell",
    r"php-cgi", r"/dev/tcp/",
]

SUSPICIOUS_PORTS = [4444, 5555, 6666, 7777, 8888, 9999, 31337, 1337, 4445]

REVERSE_SHELL = [
    r"bash -i >& /dev/tcp/", r"nc -e /bin/", r"ncat -e /bin/", r"python.*socket.*connect",
    r"perl -e.*socket", r"php -r.*fsockopen", r"sh -i >& /dev/",
]

WEBSHELL = [
    r"\$_(GET|POST|REQUEST)\[", r"eval\(\$_", r"system\(\$_", r"base64_decode\(\$_",
    r"assert\(\$_", r"shell_exec\(\$_", r"passthru\(\$_", r"preg_replace.*\/e",
]

PROMPT_INJECTION = [
    r"ignore (all )?(previous|prior|above) instructions", r"disregard .* instructions",
    r"you are now ", r"system prompt", r"new system message", r"developer message",
    r"reveal (your|the) (system )?prompt", r"print .* instructions verbatim",
    r"<\|im_start\|>system", r"\[\s*system\s*\]", r"do not follow .* policy",
    r"jailbreak", r"dan mode", r"without any (limits|restrictions|filters)",
]

# Shell history / profile tampering heuristics.
SHELL_TAMPER = REVERSE_SHELL + [
    r"alias (sudo|ls|cd|cat|rm)=", r"curl .*\| ?(sh|bash)", r"wget .*\| ?(sh|bash)",
    r">>/etc/.*(passwd|shadow|sudoers)", r"chmod \+s ", r"export .*PROMPT_COMMAND",
]

# Secrets an AI agent config should never hold in plaintext (for `ai` scan).
# Provider-specific key shapes first; the generic `sk-` catch-all last.
SECRET_PATTERNS = [
    (re.compile(r"(sk-ant-[A-Za-z0-9_-]{20,})"), "Anthropic API key"),
    (re.compile(r"(AIza[0-9A-Za-z_-]{30,})"), "Google AI (Gemini) key"),
    (re.compile(r"(sk-or-[A-Za-z0-9-]{20,})"), "OpenRouter key"),
    (re.compile(r"(gsk_[A-Za-z0-9]{20,})"), "Groq key"),
    (re.compile(r"(xai-[A-Za-z0-9]{20,})"), "xAI key"),
    (re.compile(r"(hf_[A-Za-z0-9]{20,})"), "Hugging Face token"),
    (re.compile(r"(sk-[A-Za-z0-9]{20,})"), "DeepSeek/OpenAI-compatible API key"),
    (re.compile(r"(AKIA[0-9A-Z]{16})"), "AWS access key"),
    (re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)"), "PEM private key"),
    (re.compile(r"(ghp_[A-Za-z0-9]{30,})"), "GitHub PAT"),
    (re.compile(r"(xox[bap]-[A-Za-z0-9-]{10,})"), "Slack token"),
    (re.compile(r"(glpat-[A-Za-z0-9_-]{20,})"), "GitLab PAT"),
    (re.compile(r"(\b[0-9a-f]{64}\b)"), "64-hex private key"),
    (re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"), "JWT"),
]

AI_AGENT_DIRS = [
    # agents
    "~/.hermes", "~/.claude", "~/.codex", "~/.cursor", "~/.opencode",
    "~/.config/opencode", "~/.gemini", "~/.copilot", "~/.windsurf",
    "~/Library/Application Support/Claude", "~/Library/Application Support/Cursor",
    "~/Library/Application Support/Code/User",
    # API providers
    "~/.deepseek", "~/.config/deepseek", "~/.openai", "~/.anthropic",
    "~/.openrouter", "~/.config/openrouter", "~/.groq", "~/.mistral",
    "~/.cohere", "~/.config/cohere", "~/.ollama", "~/.lmstudio",
    "~/.aider", "~/.continue", "~/.huggingface",
]

# Tool-call policy: command fragments a local/AI guard should flag or block.
DANGEROUS_TOOLS = [
    (re.compile(r"rm\s+-rf\s+(/|~|/etc|/usr|/var)"), "recursive delete of a system path"),
    (re.compile(r"curl[^\n]*\|\s*(sh|bash)"), "curl|sh pipe"),
    (re.compile(r"mkfs|dd\s+if=.*of=/dev/"), "disk wipe"),
    (re.compile(r"chmod\s+-R\s+777\s+/"), "world-writable system tree"),
    (re.compile(r"git\s+push.*--force"), "force push"),
]

# --- Web attack signatures (for the website shield / audit) ---
WEB_ATTACK = [
    (re.compile(r"(\bunion\b.+\bselect\b|\bselect\b.+\bfrom\b.+\binformation_schema\b|\bpg_sleep\b|\bsleep\s*\()", re.I), "SQL injection"),
    (re.compile(r"(<\s*script|javascript:|onerror\s*=|onclick\s*=|onload\s*=|alert\s*\(|</?script)", re.I), "XSS"),
    (re.compile(r"(\.\./\.\./|%2e%2e|\.\.%2f|%252e%252e|\.\.\\\.\.\\)", re.I), "path traversal"),
    (re.compile(r"(/etc/passwd|/etc/shadow|win\.ini|boot\.ini|\.ssh/id_rsa)", re.I), "LFI / sensitive file"),
    (re.compile(r"(\$\{[^}]*\}|\{\{[^}]*\}\}|<%=|%7b%7b)", re.I), "SSTI"),
    (re.compile(r"([;&|]\s*(cat|ls|whoami|id|wget|curl|bash|sh|nc|ncat|uname|ifconfig|ipconfig)\b)", re.I), "command injection"),
    (re.compile(r"(php://(filter|input)|expect://|file://|glob://|data://text)", re.I), "PHP wrapper injection"),
    (re.compile(r"(base64_decode\s*\(\s*\$_(GET|POST|REQUEST)|eval\s*\(\s*\$_(GET|POST|REQUEST)|assert\s*\(\s*\$_(GET|POST|REQUEST)|shell_exec\s*\(\s*\$_(GET|POST|REQUEST)|system\s*\(\s*\$_(GET|POST|REQUEST))", re.I), "PHP code injection"),
    (re.compile(r"(<\?php|<\?=)", re.I), "PHP tag injection"),
    (re.compile(r"(java\.lang\.Runtime|ProcessBuilder|getRuntime\s*\(\s*\)\.exec)", re.I), "Java RCE"),
    (re.compile(r"(select\s+pg_sleep|waitfor\s+delay|benchmark\s*\()", re.I), "blind SQLi"),
    (re.compile(r"(curl|wget|nc|ncat)[^a-z].*\|\s*(sh|bash)", re.I), "piped reverse shell"),
]

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

EXPOSED_PATHS = [
    "/.git/HEAD", "/.git/config", "/.env", "/phpinfo.php", "/info.php",
    "/backup.zip", "/backup.tar.gz", "/.DS_Store", "/server-status",
    "/wp-config.php.bak", "/.htaccess", "/.aws/credentials", "/id_rsa",
]

# Open services that are dangerous to expose on a public interface.
DANGEROUS_SERVICES = {
    23: "telnet", 21: "ftp", 3306: "mysql", 6379: "redis", 9200: "elasticsearch",
    27017: "mongodb", 5432: "postgresql", 2375: "docker (unauthenticated)",
    11211: "memcached", 5900: "vnc", 3389: "rdp", 22: "ssh", 5985: "winrm",
}

# --- Supply-chain / malicious-repo detection ---
SUPPLY_CHAIN = [
    (re.compile(r"(discord(app)?\.com/api/webhooks|hooks\.slack\.com/services|api\.telegram\.org/bot)"), "webhook exfiltration endpoint", "high"),
    (re.compile(r"(eval|exec|system|os\.system|subprocess|child_process)\(\s*(atob|Buffer\.from|base64|b64decode|unhexlify|fromhex|bytes\.fromhex)"), "obfuscated eval/exec", "high"),
    (re.compile(r"curl[^\n]*\|\s*(sh|bash|zsh)|wget[^\n]*\|\s*(sh|bash|zsh)"), "download-and-execute", "high"),
    (re.compile(r"/dev/tcp/|nc\s+-e\s|ncat\s+-e\s|bash\s+-i\s*>&|sh\s+-i\s*>&"), "reverse shell", "high"),
    (re.compile(r"(xmrig|cpuminer|xmr-stak|stratum\+tcp|pool\.minexmr|nanopool)"), "crypto miner", "high"),
    (re.compile(r"(wallet\.dat|metamask|seed\s*phrase|mnemonic|private\s*key).{0,60}(upload|send|post|fetch|exfil|webhook)"), "wallet/credential theft", "high"),
    (re.compile(r"(authorized_keys|crontab|launchctl|LaunchAgent|LaunchDaemon|systemctl\s+enable|schtasks)"), "persistence mechanism", "medium"),
    (re.compile(r"(chmod\s+\+s|chmod\s+4777|setuid|SetUID)"), "setuid escalation", "medium"),
    (re.compile(r"[A-Za-z0-9+/]{80,}={0,2}"), "long base64 blob (possible payload)", "medium"),
    (re.compile(r"(?:\\x[0-9a-fA-F]{2}){30,}"), "hex-encoded blob", "medium"),
    (re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}"), "direct IP URL", "low"),
    (re.compile(r"(process\.env\.|\.env).{0,40}(webhook|fetch|axios|requests|post|curl)"), "env var exfiltration", "high"),
    (re.compile(r"(ssh-rsa|ssh-ed25519|ecdsa-)[A-Za-z0-9+/=]{40,}"), "embedded SSH key", "medium"),
]

CODE_EXTENSIONS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".sh", ".bash",
                  ".php", ".rb", ".go", ".rs", ".sol", ".pl", ".ex", ".exs", ".java",
                  ".kt", ".cs", ".ps1", ".zsh"}

SKIP_PARTS = ["node_modules", ".git", "vendor", "dist", ".next", "__pycache__", ".venv", "site-packages", "min.js"]

POPULAR_PACKAGES = ["react", "react-dom", "lodash", "axios", "express", "next", "vue",
                    "requests", "numpy", "pandas", "flask", "django", "torch",
                    "tensorflow", "web3", "ethers", "viem", "solana-web3", "openai",
                    "anthropic", "langchain", "vite", "webpack", "typescript", "eslint",
                    "prettier", "dotenv", "crypto-js", "mysql2", "pg", "mongoose",
                    "prisma", "tailwindcss", "three", "playwright", "puppeteer",
                    "jest", "mocha", "chai", "fastapi", "uvicorn", "aiohttp", "pillow"]


def _run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except Exception as e:
        return "", str(e), -1


# ----------------------------------------------------------------------------
# scan
# ----------------------------------------------------------------------------

def scan_php():
    out, _, _ = _run("php --version 2>&1")
    m = re.search(r"PHP (\d+\.\d+\.\d+)", out or "")
    if not m:
        return []
    ver = m.group(1)
    findings = []
    branch = ".".join(ver.split(".")[:2])
    for cve in PHP_CVES:
        fx = cve["fixed"].get(branch)
        if fx and _ver_lt(ver, fx):
            findings.append({"php": ver, "cve": cve["cve"], "fixed_in": fx, "what": cve["what"], "cvss": cve["cvss"]})
    return findings


def _ver_lt(a, b):
    try:
        return tuple(map(int, a.split("."))) < tuple(map(int, b.split(".")))
    except Exception:
        return False


def scan_processes():
    hits = []
    out, _, _ = _run("ps ax -o pid,command")
    for line in out.splitlines():
        for pat in SUSPICIOUS_PROCESS:
            if re.search(pat, line, re.I):
                hits.append(line.strip()[:160])
                break
    return hits


def scan_ports():
    hits = []
    if IS_MAC:
        out, _, _ = _run("lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null")
    else:
        out, _, _ = _run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    for line in out.splitlines():
        for port in SUSPICIOUS_PORTS:
            if re.search(rf":{port}\b", line):
                hits.append(line.strip()[:160])
                break
    return hits


def scan_connections():
    hits = []
    cmd = "lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null" if IS_MAC else "ss -tnp 2>/dev/null | grep ESTAB"
    out, _, _ = _run(cmd)
    # flag connections to common C2-ish destinations is heuristic-only here;
    # report non-local, non-apple established connections.
    for line in out.splitlines():
        if re.search(r"ESTABLISHED", line) and not re.search(r"127\.0\.0\.1|::1|apple|icloud|push", line, re.I):
            hits.append(line.strip()[:160])
    return hits


def scan_launch_agents():
    hits = []
    dirs = [
        Path.home() / "Library/LaunchAgents",
        Path("/Library/LaunchAgents"),
        Path("/Library/LaunchDaemons"),
    ] if IS_MAC else [
        Path.home() / ".config/autostart",
        Path("/etc/xdg/autostart"),
    ]
    for d in dirs:
        if not d.exists():
            continue
        for f in d.glob("*"):
            if f.is_dir():
                continue
            try:
                txt = f.read_text(errors="ignore")
            except Exception:
                continue
            for pat in REVERSE_SHELL + [r"curl", r"wget", r"/dev/tcp/", r"python3?-.*socket"]:
                if re.search(pat, txt, re.I):
                    hits.append(str(f))
                    break
    return hits


def scan_shell_profiles():
    hits = []
    files = [Path.home() / f for f in [".zshrc", ".zprofile", ".bashrc", ".bash_profile", ".profile"]]
    for f in files:
        if not f.exists():
            continue
        for i, line in enumerate(f.read_text(errors="ignore").splitlines(), 1):
            for pat in SHELL_TAMPER:
                if re.search(pat, line, re.I):
                    hits.append(f"{f}:{i}: {line.strip()[:120]}")
                    break
    return hits


def scan_cron():
    hits = []
    out, _, _ = _run("crontab -l 2>/dev/null")
    for line in out.splitlines():
        for pat in REVERSE_SHELL:
            if re.search(pat, line, re.I):
                hits.append(line.strip()[:160])
                break
    return hits


def scan_webshells():
    hits = []
    # shallow sweep of common web roots for php webshell patterns
    roots = [Path.home() / "Sites", Path("/Library/WebServer/Documents"), Path("/var/www")]
    for root in roots:
        if not root.exists():
            continue
        for p in root.rglob("*.php"):
            try:
                txt = p.read_text(errors="ignore")
            except Exception:
                continue
            if len(txt) > 200_000:
                continue
            for pat in WEBSHELL:
                if re.search(pat, txt):
                    hits.append(str(p))
                    break
    return hits


def scan_defenses():
    """Report current defensive posture (macOS)."""
    r = {}
    if IS_MAC:
        out, _, _ = _run("defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null")
        r["firewall"] = "on" if out.strip() in ("1", "2") else ("block_all" if out.strip() == "2" else "off")
        out, _, _ = _run("csrutil status 2>/dev/null")
        r["sip"] = "enabled" if "enabled" in out else "disabled"
        out, _, _ = _run("spctl --status 2>&1")
        r["gatekeeper"] = "enabled" if "assessments enabled" in out else "disabled"
        out, _, _ = _run("fdesetup status 2>/dev/null")
        r["filevault"] = "on" if "On" in out else "off"
    else:
        out, _, _ = _run("cat /proc/sys/net/ipv4/ip_forward 2>/dev/null")
        r["ip_forward"] = out.strip()
    # SSH posture
    sshd = Path("/etc/ssh/sshd_config")
    if sshd.exists():
        txt = sshd.read_text(errors="ignore")
        r["ssh_password_auth"] = "on" if re.search(r"^\s*PasswordAuthentication\s+yes", txt, re.M) else "off"
        r["ssh_root_login"] = "on" if re.search(r"^\s*PermitRootLogin\s+(yes|without-password)", txt, re.M) else "off"
    return r


def do_scan():
    report = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "platform": platform.platform(),
        "php_vulnerabilities": scan_php(),
        "suspicious_processes": scan_processes(),
        "suspicious_ports": scan_ports(),
        "established_connections": scan_connections(),
        "suspicious_launch_agents": scan_launch_agents(),
        "shell_tampering": scan_shell_profiles(),
        "suspicious_cron": scan_cron(),
        "webshells": scan_webshells(),
        "defenses": scan_defenses(),
    }
    return report


# ----------------------------------------------------------------------------
# harden
# ----------------------------------------------------------------------------

def harden(dry_run=True):
    actions = []
    if IS_MAC:
        fw, _, _ = _run("defaults read /Library/Preferences/com.apple.alf globalstate 2>/dev/null")
        if fw.strip() != "1":
            actions.append("sudo defaults write /Library/Preferences/com.apple.alf globalstate -int 1")
        actions.append("sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setblockall off --setstealthmode on")
    sshd = Path("/etc/ssh/sshd_config")
    if sshd.exists():
        txt = sshd.read_text(errors="ignore")
        if re.search(r"^\s*PasswordAuthentication\s+yes", txt, re.M):
            actions.append("sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config")
        if re.search(r"^\s*PermitRootLogin\s+yes", txt, re.M):
            actions.append("sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config")

    if dry_run:
        return actions
    # Apply only explicit, low-risk actions that do not require sudo password here;
    # report the rest for the operator to run.
    applied = []
    for a in actions:
        if a.startswith("sudo "):
            continue  # needs elevation — report, don't run blindly
        out, err, rc = _run(a)
        applied.append({"cmd": a, "rc": rc, "err": err.strip()[:120]})
    return applied


# ----------------------------------------------------------------------------
# guard (continuous monitor)
# ----------------------------------------------------------------------------

def guard(interval=30, once=False):
    prev = set()
    while True:
        proc = set(scan_processes())
        ports = set(scan_ports())
        launch = set(scan_launch_agents())
        shell = set(scan_shell_profiles())
        now = proc | ports | launch | shell
        new = now - prev
        if prev and new:
            print(f"[!] NEW SUSPICIOUS ACTIVITY ({time.strftime('%H:%M:%S')}):")
            for x in new:
                print(f"    {x}")
        prev = now
        if once:
            break
        time.sleep(interval)


# ----------------------------------------------------------------------------
# ai (defend AI agents)
# ----------------------------------------------------------------------------

def ai_secret_scan():
    hits = []
    SKIP = ["node_modules", "/openssl/", "/include/", ".git", ".DS_Store", "fipskey", "__pycache__", "tools/", "site-packages"]
    for d in AI_AGENT_DIRS:
        base = Path(d).expanduser()
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if p.is_dir():
                continue
            sp = str(p)
            if any(s in sp for s in SKIP):
                continue
            if p.suffix in {".log", ".db", ".sqlite", ".jsonl", ".pyc", ".h"}:
                continue
            try:
                if p.stat().st_size > 500_000:
                    continue
                txt = p.read_text(errors="ignore")
            except Exception:
                continue
            for pat, label in SECRET_PATTERNS:
                for m in pat.finditer(txt):
                    hits.append({"file": sp, "kind": label, "line": txt[:m.start()].count("\n") + 1})
                    break
    return hits


def ai_injection_check(text):
    if not text:
        return []
    return [p for p in PROMPT_INJECTION if re.search(p, text, re.I)]


def ai_tool_policy(command):
    flags = []
    for pat, why in DANGEROUS_TOOLS:
        if pat.search(command):
            flags.append({"command": command[:160], "why": why, "verdict": "BLOCK"})
    return flags


def do_ai(args):
    out = {}
    if args.secrets or (not args.text and not args.tool):
        out["secret_leaks"] = ai_secret_scan()
    if args.text:
        out["injection_flags"] = ai_injection_check(args.text)
    if args.tool:
        out["tool_policy"] = ai_tool_policy(args.tool)
    return out


# ----------------------------------------------------------------------------
# web (website fortress)
# ----------------------------------------------------------------------------

def web_audit(url):
    if not url.startswith("http"):
        url = "https://" + url
    report = {"url": url, "headers": {}, "missing_headers": [], "exposed": []}
    try:
        req = urllib.request.Request(url, method="GET", headers={"User-Agent": "VANGUARD/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            report["status"] = resp.status
            for k, v in resp.headers.items():
                report["headers"][k.lower()] = v
    except Exception as e:
        report["error"] = str(e)
        return report

    for h in SECURITY_HEADERS:
        if h not in report["headers"]:
            report["missing_headers"].append(h)
    if "server" in report["headers"]:
        report["server_header"] = report["headers"]["server"]
    if url.startswith("http://"):
        report["tls"] = "NO — plain HTTP"

    base = url.rstrip("/")
    for path in EXPOSED_PATHS:
        try:
            r = urllib.request.Request(base + path, method="GET", headers={"User-Agent": "VANGUARD/1.0"})
            with urllib.request.urlopen(r, timeout=8) as resp:
                report["exposed"].append({"path": path, "status": resp.status})
        except urllib.error.HTTPError as e:
            if e.code not in (404, 410):
                report["exposed"].append({"path": path, "status": e.code, "note": "exists (non-404)"})
        except Exception:
            pass
    return report


def web_shield(upstream, port=8080):
    """Reverse-proxy WAF: sits in front of a site and blocks attack payloads."""
    upstream = upstream.rstrip("/")

    class Shield(http.server.BaseHTTPRequestHandler):
        def _handle(self):
            raw = self.path
            body = b""
            clen = self.headers.get("Content-Length")
            if clen and clen.isdigit():
                body = self.rfile.read(int(clen))
            raw += "\n" + str(self.headers) + "\n" + body.decode("utf-8", "ignore")

            for pat, why in WEB_ATTACK:
                if pat.search(raw):
                    self.log_message("BLOCKED [%s] %s", why, self.path)
                    self.send_response(403)
                    self.send_header("Content-Type", "text/plain")
                    self.end_headers()
                    self.wfile.write(b"403 Forbidden - blocked by VANGUARD\n")
                    return

            fwd = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length", "connection")}
            fwd["Host"] = urllib.parse.urlparse(upstream).netloc
            try:
                req = urllib.request.Request(upstream + self.path, data=body or None, method=self.command, headers=fwd)
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = resp.read()
                    self.send_response(resp.status)
                    for k, v in resp.headers.items():
                        if k.lower() not in ("transfer-encoding", "connection", "content-length"):
                            self.send_header(k, v)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
            except Exception as e:
                self.log_message("UPSTREAM ERROR: %s", e)
                self.send_response(502)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"502 Bad Gateway\n")

        def do_GET(self): self._handle()
        def do_POST(self): self._handle()
        def do_PUT(self): self._handle()
        def do_DELETE(self): self._handle()
        def do_HEAD(self): self._handle()
        def do_OPTIONS(self): self._handle()
        def log_message(self, fmt, *args):
            print("[%s] %s" % (time.strftime("%H:%M:%S"), fmt % args), flush=True)

    class Reuse(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    print(f"VANGUARD shield listening: http://127.0.0.1:{port}  ->  {upstream}")
    print("Forward this to your site instead of exposing the origin directly.")
    with Reuse(("127.0.0.1", port), Shield) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nshield stopped")


def net_audit():
    """Self network audit: what is listening, and whether any are dangerous."""
    hits = []
    out, _, _ = _run("lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null" if IS_MAC else "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    for line in out.splitlines():
        m = re.search(r":(\d+)\s", line)
        if not m:
            continue
        port = int(m.group(1))
        if port in DANGEROUS_SERVICES:
            hits.append({"port": port, "service": DANGEROUS_SERVICES[port], "line": line.strip()[:140]})
    return {"listening": len(out.splitlines()), "dangerous_services": hits}


def _lev(a, b):
    """Levenshtein edit distance."""
    la, lb = len(a), len(b)
    if la > lb:
        a, b, la, lb = b, a, lb, la
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] != b[j - 1]))
        prev = cur
    return prev[lb]


def repo_scan(target):
    """Scan a GitHub URL or local directory for malicious supply-chain code."""
    import shutil as _sh
    import tempfile
    findings = []
    tmp = None
    root = target
    if target.startswith(("http://", "https://", "git@", "ssh://")):
        tmp = tempfile.mkdtemp(prefix="vanguard-repo-")
        out, err, rc = _run(f"git clone --depth 1 --quiet '{target}' '{tmp}'", timeout=120)
        if rc != 0:
            return {"target": target, "verdict": "error", "error": f"clone failed: {err.strip()[:200]}"}
        root = tmp

    name = Path(root).name.lower().replace(".git", "").replace("-", "").replace("_", "")
    name_hits = []
    for pkg in POPULAR_PACKAGES:
        pn = pkg.replace("-", "").replace("_", "")
        if name == pn:
            name_hits = []
            break
        if len(name) >= 4 and _lev(name, pn) <= 1:
            name_hits.append(pkg)

    try:
        for p in Path(root).rglob("*"):
            if p.is_dir():
                continue
            sp = str(p)
            if any(s in sp for s in SKIP_PARTS):
                continue
            if p.suffix.lower() not in CODE_EXTENSIONS and p.name not in (
                "package.json", "setup.py", "pyproject.toml", "requirements.txt",
                "Cargo.toml", "go.mod", "Makefile", "Dockerfile"):
                continue
            try:
                if p.stat().st_size > 2_000_000:
                    continue
                txt = p.read_text(errors="ignore")
            except Exception:
                continue
            for pat, label, sev in SUPPLY_CHAIN:
                m = pat.search(txt)
                if m:
                    line = txt[:m.start()].count("\n") + 1
                    findings.append({"file": sp[len(str(root)) + 1:], "line": line, "what": label, "severity": sev})
            if p.name == "package.json":
                try:
                    j = json.loads(txt)
                    for hook in ("preinstall", "postinstall", "install"):
                        cmd = j.get("scripts", {}).get(hook, "")
                        if re.search(r"curl|wget|\bsh\b|\bbash\b|node\s+-e|python\s+-c|\beval\b", cmd, re.I):
                            findings.append({"file": p.name, "line": 0, "what": f"{hook} hook runs: {cmd[:80]}", "severity": "high"})
                except Exception:
                    pass
            if p.name in ("package.json", "requirements.txt"):
                deps = []
                if p.name == "package.json":
                    try:
                        j = json.loads(txt)
                        deps = list(j.get("dependencies", {}).keys()) + list(j.get("devDependencies", {}).keys())
                    except Exception:
                        pass
                else:
                    for ln in txt.splitlines():
                        m2 = re.match(r"\s*([A-Za-z0-9._-]+)", ln)
                        if m2:
                            deps.append(m2.group(1))
                for d in deps:
                    dn = d.lower().replace("-", "").replace("_", "")
                    for pkg in POPULAR_PACKAGES:
                        pn = pkg.replace("-", "").replace("_", "")
                        if dn != pn and len(dn) >= 4 and _lev(dn, pn) <= 1:
                            findings.append({"file": p.name, "line": 0, "what": f"possible typosquat: '{d}' ~ '{pkg}'", "severity": "low"})
                            break
    finally:
        if tmp:
            _sh.rmtree(tmp, ignore_errors=True)

    verdict = "clean"
    if any(f["severity"] == "high" for f in findings):
        verdict = "MALICIOUS"
    elif findings:
        verdict = "suspicious"
    if name_hits:
        findings.append({"file": "(repo name)", "line": 0, "what": f"name close to '{name_hits[0]}'", "severity": "low"})
    return {"target": target, "verdict": verdict, "total": len(findings), "findings": findings}


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(prog="vanguard", description="Local machine + AI agent defense")
    p.add_argument("--version", action="version", version=f"vanguard {VERSION}")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("scan", help="full local threat scan")

    hp = sub.add_parser("harden", help="apply defenses")
    hp.add_argument("--yes", action="store_true", help="apply (without this, prints a dry-run plan)")

    gp = sub.add_parser("guard", help="continuous monitor")
    gp.add_argument("--interval", type=int, default=30)
    gp.add_argument("--once", action="store_true")

    ap = sub.add_parser("ai", help="defend AI agents (secret scan by default)")
    ap.add_argument("--secrets", action="store_true", help="scan agent configs for plaintext secrets")
    ap.add_argument("--text", help="text to check for prompt-injection patterns")
    ap.add_argument("--tool", help="tool/command to check against the tool policy")

    sub.add_parser("php", help="check local PHP against known CVEs")

    web = sub.add_parser("web", help="website fortress")
    web_sub = web.add_subparsers(dest="web_cmd", required=True)
    wa = web_sub.add_parser("audit", help="audit a website's security posture")
    wa.add_argument("url")
    ws = web_sub.add_parser("shield", help="run the reverse-proxy WAF in front of a site")
    ws.add_argument("upstream")
    ws.add_argument("--port", type=int, default=8080)

    sub.add_parser("net", help="self network audit (listening services)")

    rp = sub.add_parser("repo", help="supply-chain scan of a GitHub repo or local dir")
    rp.add_argument("target")

    args = p.parse_args()

    if args.cmd == "scan":
        print(json.dumps(do_scan(), indent=2))
    elif args.cmd == "php":
        res = scan_php()
        if not res:
            print("No PHP install found, or no matching CVEs for the installed version.")
        for r in res:
            print(f"{r['cve']} [{r['cvss']}] PHP {r['php']} < {r['fixed_in']}: {r['what']}")
    elif args.cmd == "harden":
        plan = harden(dry_run=not args.yes)
        if not args.yes:
            print("DRY RUN — actions that would be applied (sudo ones need your elevation):")
        for a in plan:
            print("  " + (a if isinstance(a, str) else a.get("cmd", str(a))))
    elif args.cmd == "guard":
        try:
            guard(args.interval, args.once)
        except KeyboardInterrupt:
            print("\nstopped")
    elif args.cmd == "ai":
        print(json.dumps(do_ai(args), indent=2))
    elif args.cmd == "web":
        if args.web_cmd == "audit":
            print(json.dumps(web_audit(args.url), indent=2))
        elif args.web_cmd == "shield":
            web_shield(args.upstream, args.port)
    elif args.cmd == "net":
        print(json.dumps(net_audit(), indent=2))
    elif args.cmd == "repo":
        print(json.dumps(repo_scan(args.target), indent=2))


if __name__ == "__main__":
    main()
