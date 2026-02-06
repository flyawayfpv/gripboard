"""Per-application rule profiles and active window detection."""

import os
import shutil
import subprocess
from dataclasses import dataclass, field

from gripboard.monitor import detect_display_server


@dataclass
class AppProfile:
    """Override scanner settings for a specific application."""
    name: str
    # Which WM_CLASS / app_id values match this profile
    match: list[str] = field(default_factory=list)
    # Override toggles (None = inherit from global config)
    check_ascii: bool | None = None
    check_homoglyphs: bool | None = None
    check_invisible: bool | None = None
    check_bidi: bool | None = None
    # Extra allowed codepoints for this app
    allowed_codepoints: set[int] = field(default_factory=set)
    # Whether to show the confirmation dialog
    confirm_paste: bool = True


# --- Active window detection ---

def get_active_window_class() -> str | None:
    """Get the WM_CLASS or app_id of the currently focused window."""
    server = detect_display_server()
    if server == "x11":
        return _get_x11_window_class()
    elif server == "wayland":
        return _get_wayland_app_id()
    return None


def _get_x11_window_class() -> str | None:
    """Use xdotool + xprop to get the active window's WM_CLASS."""
    if not shutil.which("xdotool") or not shutil.which("xprop"):
        return None
    try:
        wid = subprocess.check_output(
            ["xdotool", "getactivewindow"],
            timeout=2,
            stderr=subprocess.DEVNULL,
        ).decode().strip()

        xprop_out = subprocess.check_output(
            ["xprop", "-id", wid, "WM_CLASS"],
            timeout=2,
            stderr=subprocess.DEVNULL,
        ).decode().strip()

        # Format: WM_CLASS(STRING) = "instance", "class"
        if "=" in xprop_out:
            raw = xprop_out.split("=", 1)[1].strip()
            parts = [p.strip().strip('"') for p in raw.split(",")]
            # Return the class name (second element) or instance
            return parts[-1] if parts else None

    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError):
        pass
    return None


def _get_wayland_app_id() -> str | None:
    """Attempt to get the focused app_id on Wayland.

    This is compositor-dependent. We try swaymsg (sway/i3) and
    hyprctl (Hyprland) as the most common tiling WMs on Wayland.
    GNOME/KDE don't expose this easily without a portal.
    """
    # Try sway / i3
    if shutil.which("swaymsg"):
        try:
            import json
            out = subprocess.check_output(
                ["swaymsg", "-t", "get_tree"],
                timeout=2,
                stderr=subprocess.DEVNULL,
            ).decode()
            tree = json.loads(out)
            focused = _find_focused_sway(tree)
            if focused:
                return focused.get("app_id") or focused.get("window_properties", {}).get("class")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError, ValueError):
            pass

    # Try Hyprland
    if shutil.which("hyprctl"):
        try:
            out = subprocess.check_output(
                ["hyprctl", "activewindow", "-j"],
                timeout=2,
                stderr=subprocess.DEVNULL,
            ).decode()
            import json
            data = json.loads(out)
            return data.get("class") or data.get("initialClass")
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError, OSError, ValueError):
            pass

    return None


def _find_focused_sway(node: dict) -> dict | None:
    """Recursively find the focused node in a sway tree."""
    if node.get("focused"):
        return node
    for child in node.get("nodes", []) + node.get("floating_nodes", []):
        result = _find_focused_sway(child)
        if result:
            return result
    return None


def resolve_profile(
    app_class: str | None,
    profiles: list[AppProfile],
) -> AppProfile | None:
    """Find the first matching profile for the given window class."""
    if not app_class:
        return None
    app_lower = app_class.lower()
    for profile in profiles:
        for pattern in profile.match:
            if pattern.lower() in app_lower:
                return profile
    return None


# --- Default built-in profiles ---

BUILTIN_PROFILES = [
    AppProfile(
        name="terminal",
        match=[
            "kitty", "alacritty", "gnome-terminal", "konsole",
            "xfce4-terminal", "xterm", "terminator", "tilix",
            "wezterm", "foot", "st-256color", "urxvt",
        ],
        # Strict: all checks on, always confirm
        check_ascii=True,
        check_homoglyphs=True,
        check_invisible=True,
        check_bidi=True,
        confirm_paste=True,
    ),
    AppProfile(
        name="browser",
        match=[
            "firefox", "chromium", "google-chrome", "brave-browser",
            "vivaldi", "opera", "epiphany", "librewolf",
        ],
        # Relaxed: skip non-ascii (URLs/forms often have international chars)
        check_ascii=False,
        check_homoglyphs=True,
        check_invisible=True,
        check_bidi=True,
        confirm_paste=False,
    ),
    AppProfile(
        name="editor",
        match=[
            "code", "vscodium", "sublime_text", "gedit", "kate",
            "emacs", "gvim", "jetbrains",
        ],
        check_ascii=True,
        check_homoglyphs=True,
        check_invisible=True,
        check_bidi=True,
        confirm_paste=True,
    ),
]
