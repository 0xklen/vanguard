<p align="center">
  <img src="assets/logo.svg" width="96" alt="VANGUARD" />
</p>

<h1 align="center">VANGUARD</h1>

<p align="center">
  The first and last line of defense for your local machine, your AI agents, and everything they run.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue" alt="python" />
  <img src="https://img.shields.io/badge/deps-none-green" alt="deps" />
  <img src="https://img.shields.io/badge/license-MIT-lightgrey" alt="license" />
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightblue" alt="platform" />
</p>

---

VANGUARD is a zero-dependency guardian that watches your machine and your
agents, and acts as the forward guard against the exploits that keep showing
up — the October 2026 PHP memory-corruption and object-injection wave, plus
the standing catalog of local compromise: reverse shells, webshells, miners,
launch-agent persistence, shell-profile tampering, and AI prompt injection.

It does not phone home, ships no telemetry, and needs no network to run.

## Quick start

```bash
git clone https://github.com/0xklen/vanguard
cd vanguard

python3 vanguard.py scan          # full threat scan of this machine
python3 vanguard.py harden        # dry-run the defense plan
python3 vanguard.py harden --yes  # apply it
python3 vanguard.py guard         # keep watching; alert on new activity
python3 vanguard.py ai            # scan your AI agents for leaked secrets
python3 vanguard.py ai --text "…" # check text for prompt-injection patterns
python3 vanguard.py ai --tool "…" # check a command against the tool policy
python3 vanguard.py php           # check local PHP against the 2026 CVEs
```

No `pip install`. No compiled deps. Python 3.8+ only.

## What it defends against

| Vector | What VANGUARD does |
| --- | --- |
| **PHP exploit wave** | Detects a local PHP install below the fixed versions for the 2026 CVEs (openssl_encrypt memory corruption, metaphone() overflow, Saloon/Alliance object injection) |
| **Reverse shells** | Scans running processes, cron, launch agents and shell profiles for `bash -i >& /dev/tcp/`, `nc -e`, `python socket` and friends |
| **Webshells** | Sweeps common web roots for `eval($_GET…)`, `base64_decode($_…)`, `shell_exec($_…)` signatures |
| **Crypto miners & stealers** | Flags xmrig, kinsing, kdevtmpfsi, mimikatz, beacon and similar process names |
| **Persistence** | Reads LaunchAgents/LaunchDaemons and autostart entries for suspicious payloads |
| **Shell tampering** | Detects aliased `sudo`/`ls`, `curl \| sh` one-liners, `/etc/sudoers` appends in your profiles |
| **AI prompt injection** | Flags "ignore previous instructions", "reveal your system prompt", fake system/developer frames, jailbreak phrasings |
| **AI secret leakage** | Scans `~/.hermes`, `~/.claude`, `~/.codex`, `~/.cursor` and others for plaintext API keys, private keys, PATs and JWTs |
| **Dangerous tool calls** | Blocks `rm -rf /`, `curl \| sh`, disk wipes, `chmod -R 777 /`, force-push patterns |

## Commands

### `scan`

Reads the machine's real state — processes, listening ports, established
connections, launch agents, cron, shell profiles, webshells, PHP version and
the current defensive posture (firewall, SIP, Gatekeeper, FileVault, SSH) —
and reports anything that matches the threat catalog.

```bash
python3 vanguard.py scan
```

Output is JSON. Pipe it through `jq` or your agent's tooling.

### `harden`

Prints the defense plan by default. `--yes` applies the non-elevated actions;
anything needing `sudo` is listed for you to run deliberately, because a
guardian should never elevate itself behind your back.

### `guard`

Continuous monitor. Takes a baseline, then alerts whenever a new suspicious
process, port, launch agent or profile line appears.

```bash
python3 vanguard.py guard --interval 30
```

### `ai`

Defends the AI layer — the part of your setup that can be talked into doing
things the machine would never do on its own.

```bash
python3 vanguard.py ai                  # secret-leak scan of agent configs
python3 vanguard.py ai --text "..."     # prompt-injection check
python3 vanguard.py ai --tool "..."     # tool-call policy verdict
```

### `php`

Checks `php --version` against the known 2026 CVEs and prints the ones your
install is still exposed to.

## How it works

Everything is pattern-driven and read-only by default. VANGUARD keeps a small,
editable threat catalog in the source — the CVEs, process names, ports,
webshell and injection signatures are all plain lists you can extend. The
`guard` mode diffs the machine against its own baseline so it catches *new*
activity, not just the stuff that was already there.

No daemon, no root by default, no outbound traffic. It is a vanguard in the
literal sense: a forward observer that reports, and a shield that you raise
when you choose to.

## The 2026 PHP wave (why this exists)

- **CVE-2026-14355** — ext/openssl memory corruption in `openssl_encrypt()` with AES-WRAP-PAD.
- **CVE-2026-7568** — `metaphone()` buffer overflow via an oversized string.
- **CVE-2026-33942** — Saloon PHP library insecure deserialization.
- **CVE-2026-78529** — unauthenticated PHP object injection (Alliance ≤ 3.11).
- **CVE-2024-4577** — PHP-CGI argument injection (RCE).

`vanguard php` tells you at a glance whether the PHP on your machine is still
in the blast radius.

## FAQ

**Does it need root?** No. Scans run as your user; `harden` lists `sudo`
actions for you to run yourself.

**Does it block anything automatically?** No — `guard` and `ai --tool` report
verdicts. Raising the shield is explicit.

**macOS or Linux?** Both. macOS gets firewall/SIP/Gatekeeper/FileVault checks;
Linux gets `ss`/`netstat` and sysctl checks.

**Can I add my own indicators?** Yes — the threat lists are plain Python
constants at the top of `vanguard.py`.

## License

MIT. See [LICENSE](LICENSE).
