"""Configuration management using TOML."""

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from gripboard.profiles import AppProfile

DEFAULT_CONFIG_DIR = Path(os.environ.get(
    "XDG_CONFIG_HOME", os.path.expanduser("~/.config")
)) / "gripboard"

DEFAULT_CONFIG_PATH = DEFAULT_CONFIG_DIR / "config.toml"

DEFAULT_CONFIG = """\
# Gripboard configuration

[scanner]
# Enable/disable individual check modules
check_ascii = true
check_homoglyphs = true
check_invisible = true
check_bidi = true

[scanner.allowlist]
# Unicode codepoints to ignore (hex values without 0x prefix)
# Example: codepoints = ["00E9", "00F1"]  # é, ñ
codepoints = []

[notifications]
# "terminal" = print to stderr, "desktop" = use notify-send, "both" = both
mode = "both"

# Minimum severity to trigger a notification: safe, low, medium, high, critical
min_severity = "low"

[monitor]
# Polling interval in seconds (X11 only; Wayland uses event-driven watching)
poll_interval = 0.5

# Show confirmation dialog on suspicious paste (requires GUI mode)
confirm_paste = true

# Use per-application profiles (terminal=strict, browser=relaxed, etc.)
use_profiles = true

# Uncomment to define custom app profiles:
# [[profiles]]
# name = "my-terminal"
# match = ["alacritty", "kitty"]
# check_ascii = true
# check_homoglyphs = true
# check_invisible = true
# check_bidi = true
# confirm_paste = true
# allowed_codepoints = []

[community]
# API URL for community rules and telemetry
api_url = "https://api.gripboard.dev"

# Opt-in anonymous telemetry (only sends aggregate counts, never clipboard content)
telemetry = false

# Auto-sync community rules on startup
auto_sync = false
"""


@dataclass
class ScannerConfig:
    check_ascii: bool = True
    check_homoglyphs: bool = True
    check_invisible: bool = True
    check_bidi: bool = True
    allowed_codepoints: set[int] = field(default_factory=set)


@dataclass
class NotificationConfig:
    mode: str = "both"  # terminal, desktop, both
    min_severity: str = "low"


@dataclass
class MonitorConfig:
    poll_interval: float = 0.5
    confirm_paste: bool = True
    use_profiles: bool = True


@dataclass
class CommunityConfig:
    api_url: str = "https://api.gripboard.dev"
    telemetry: bool = False
    auto_sync: bool = False


@dataclass
class GripboardConfig:
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    notifications: NotificationConfig = field(default_factory=NotificationConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    community: CommunityConfig = field(default_factory=CommunityConfig)
    profiles: list[AppProfile] = field(default_factory=list)


def load_config(path: Path | None = None) -> GripboardConfig:
    """Load configuration from a TOML file, falling back to defaults."""
    config = GripboardConfig()
    config_path = path or DEFAULT_CONFIG_PATH

    if not config_path.exists():
        return config

    with open(config_path, "rb") as f:
        raw = tomllib.load(f)

    # Scanner settings
    scanner_raw = raw.get("scanner", {})
    if "check_ascii" in scanner_raw:
        config.scanner.check_ascii = bool(scanner_raw["check_ascii"])
    if "check_homoglyphs" in scanner_raw:
        config.scanner.check_homoglyphs = bool(scanner_raw["check_homoglyphs"])
    if "check_invisible" in scanner_raw:
        config.scanner.check_invisible = bool(scanner_raw["check_invisible"])
    if "check_bidi" in scanner_raw:
        config.scanner.check_bidi = bool(scanner_raw["check_bidi"])

    allowlist = scanner_raw.get("allowlist", {})
    codepoints = allowlist.get("codepoints", [])
    config.scanner.allowed_codepoints = {int(cp, 16) for cp in codepoints}

    # Notification settings
    notif_raw = raw.get("notifications", {})
    if "mode" in notif_raw:
        config.notifications.mode = str(notif_raw["mode"])
    if "min_severity" in notif_raw:
        config.notifications.min_severity = str(notif_raw["min_severity"])

    # Monitor settings
    monitor_raw = raw.get("monitor", {})
    if "poll_interval" in monitor_raw:
        config.monitor.poll_interval = float(monitor_raw["poll_interval"])
    if "confirm_paste" in monitor_raw:
        config.monitor.confirm_paste = bool(monitor_raw["confirm_paste"])
    if "use_profiles" in monitor_raw:
        config.monitor.use_profiles = bool(monitor_raw["use_profiles"])

    # Community settings
    community_raw = raw.get("community", {})
    if "api_url" in community_raw:
        config.community.api_url = str(community_raw["api_url"])
    if "telemetry" in community_raw:
        config.community.telemetry = bool(community_raw["telemetry"])
    if "auto_sync" in community_raw:
        config.community.auto_sync = bool(community_raw["auto_sync"])

    # App profiles
    for p in raw.get("profiles", []):
        config.profiles.append(AppProfile(
            name=p.get("name", "custom"),
            match=p.get("match", []),
            check_ascii=p.get("check_ascii"),
            check_homoglyphs=p.get("check_homoglyphs"),
            check_invisible=p.get("check_invisible"),
            check_bidi=p.get("check_bidi"),
            confirm_paste=p.get("confirm_paste", True),
            allowed_codepoints={int(cp, 16) for cp in p.get("allowed_codepoints", [])},
        ))

    return config


def init_config(path: Path | None = None) -> Path:
    """Create a default config file if one doesn't exist. Returns the path."""
    config_path = path or DEFAULT_CONFIG_PATH
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if not config_path.exists():
        config_path.write_text(DEFAULT_CONFIG)
    return config_path
