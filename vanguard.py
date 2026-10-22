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
"""
import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import time
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
SECRET_PATTERNS = [
    (re.compile(r"(sk-[A-Za-z0-9]{20,})"), "OpenAI-style API key"),
    (re.compile(r"(AKIA[0-9A-Z]{16})"), "AWS access key"),
    (re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)"), "PEM private key"),
    (re.compile(r"(ghp_[A-Za-z0-9]{30,})"), "GitHub PAT"),
    (re.compile(r"(xox[bap]-[A-Za-z0-9-]{10,})"), "Slack token"),
    (re.compile(r"(glpat-[A-Za-z0-9_-]{20,})"), "GitLab PAT"),
    (re.compile(r"(\b[0-9a-f]{64}\b)"), "64-hex private key"),
    (re.compile(r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"), "JWT"),
]

AI_AGENT_DIRS = [
    "~/.hermes", "~/.claude", "~/.codex", "~/.cursor", "~/.opencode",
    "~/.config/opencode", "~/.gemini", "~/.copilot", "~/.windsurf",
]

# Tool-call policy: command fragments a local/AI guard should flag or block.
DANGEROUS_TOOLS = [
    (re.compile(r"rm\s+-rf\s+(/|~|/etc|/usr|/var)"), "recursive delete of a system path"),
    (re.compile(r"curl[^\n]*\|\s*(sh|bash)"), "curl|sh pipe"),
    (re.compile(r"mkfs|dd\s+if=.*of=/dev/"), "disk wipe"),
    (re.compile(r"chmod\s+-R\s+777\s+/"), "world-writable system tree"),
    (re.compile(r"git\s+push.*--force"), "force push"),
]


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
    SKIP = ["node_modules", "/openssl/", "/include/", ".git", ".DS_Store", "fipskey", "__pycache__"]
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


if __name__ == "__main__":
    main()
