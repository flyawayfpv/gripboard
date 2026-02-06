"""Clipboard monitoring for X11 and Wayland."""

import os
import shutil
import subprocess
import time
from typing import Callable


def detect_display_server() -> str:
    """Detect whether the session is running Wayland or X11."""
    xdg_session = os.environ.get("XDG_SESSION_TYPE", "").lower()
    if xdg_session == "wayland":
        return "wayland"
    if xdg_session == "x11":
        return "x11"
    # Fallback heuristics
    if os.environ.get("WAYLAND_DISPLAY"):
        return "wayland"
    if os.environ.get("DISPLAY"):
        return "x11"
    return "unknown"


def _find_x11_tool() -> str | None:
    """Find an available X11 clipboard tool."""
    for tool in ("xclip", "xsel"):
        if shutil.which(tool):
            return tool
    return None


def _read_x11_clipboard(tool: str) -> str | None:
    """Read current X11 clipboard contents."""
    try:
        if tool == "xclip":
            cmd = ["xclip", "-selection", "clipboard", "-o"]
        else:
            cmd = ["xsel", "--clipboard", "--output"]
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=2,
        )
        if result.returncode == 0:
            return result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def watch_x11(callback: Callable[[str], None], poll_interval: float = 0.5) -> None:
    """Poll the X11 clipboard for changes and invoke callback on new content."""
    tool = _find_x11_tool()
    if tool is None:
        raise RuntimeError(
            "No X11 clipboard tool found. Install xclip or xsel."
        )

    last_content: str | None = None
    while True:
        content = _read_x11_clipboard(tool)
        if content is not None and content != last_content:
            last_content = content
            if content:  # skip empty clipboard
                callback(content)
        time.sleep(poll_interval)


def watch_wayland(callback: Callable[[str], None]) -> None:
    """Use wl-paste --watch to stream clipboard changes on Wayland."""
    if not shutil.which("wl-paste"):
        raise RuntimeError(
            "wl-paste not found. Install wl-clipboard."
        )

    # wl-paste --watch invokes a command each time the clipboard changes.
    # We use it to cat each new selection to stdout and read line-buffered.
    proc = subprocess.Popen(
        ["wl-paste", "--watch", "cat"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    assert proc.stdout is not None

    buf: list[str] = []
    last_content: str | None = None
    try:
        for line in proc.stdout:
            # wl-paste --watch cat outputs the full clipboard each time,
            # terminated when the next change arrives. We accumulate and
            # detect boundaries by a brief read timeout. For simplicity,
            # treat each line as a clipboard event; real multi-line content
            # will fire multiple callbacks but the scanner is idempotent.
            content = line
            if content != last_content:
                last_content = content
                if content.strip():
                    callback(content)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        proc.wait()


def watch_clipboard(callback: Callable[[str], None], poll_interval: float = 0.5) -> None:
    """Auto-detect display server and watch the clipboard."""
    server = detect_display_server()
    if server == "wayland":
        watch_wayland(callback)
    elif server == "x11":
        watch_x11(callback, poll_interval)
    else:
        # Try X11 first, fall back to wayland
        try:
            watch_x11(callback, poll_interval)
        except RuntimeError:
            watch_wayland(callback)
