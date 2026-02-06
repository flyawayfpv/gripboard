"""Clipboard content sanitizer — strips or replaces dangerous characters."""

import shutil
import subprocess

from gripboard.monitor import detect_display_server
from gripboard.scanner import (
    BIDI_CODEPOINTS,
    CONFUSABLES,
    INVISIBLE_CHARS,
    ScanResult,
)


def sanitize(result: ScanResult) -> str:
    """Return a sanitized version of the scanned content.

    Strategy:
    - Invisible characters: removed entirely
    - Bidi control characters: removed entirely
    - Homoglyphs: replaced with their ASCII equivalent
    - Other non-ASCII: left alone (they're flagged as LOW and are often legitimate)
    """
    chars = list(result.content)

    # Build a set of positions to remove and positions to replace
    removals: set[int] = set()
    replacements: dict[int, str] = {}

    for finding in result.findings:
        cp = ord(finding.char)
        if finding.rule == "invisible-char" or cp in INVISIBLE_CHARS:
            removals.add(finding.position)
        elif finding.rule == "bidi-control" or cp in BIDI_CODEPOINTS:
            removals.add(finding.position)
        elif finding.rule == "homoglyph" and cp in CONFUSABLES:
            replacements[finding.position] = CONFUSABLES[cp]

    output: list[str] = []
    for i, ch in enumerate(chars):
        if i in removals:
            continue
        elif i in replacements:
            output.append(replacements[i])
        else:
            output.append(ch)

    return "".join(output)


def write_clipboard(content: str) -> bool:
    """Write sanitized content back to the system clipboard.

    Returns True on success.
    """
    server = detect_display_server()

    try:
        if server == "wayland" and shutil.which("wl-copy"):
            proc = subprocess.Popen(
                ["wl-copy"],
                stdin=subprocess.PIPE,
                timeout=5,
            )
            proc.communicate(input=content.encode(), timeout=5)
            return proc.returncode == 0

        elif shutil.which("xclip"):
            proc = subprocess.Popen(
                ["xclip", "-selection", "clipboard"],
                stdin=subprocess.PIPE,
            )
            proc.communicate(input=content.encode(), timeout=5)
            return proc.returncode == 0

        elif shutil.which("xsel"):
            proc = subprocess.Popen(
                ["xsel", "--clipboard", "--input"],
                stdin=subprocess.PIPE,
            )
            proc.communicate(input=content.encode(), timeout=5)
            return proc.returncode == 0

    except (subprocess.TimeoutExpired, OSError):
        pass

    return False


def clear_clipboard() -> bool:
    """Clear the system clipboard. Returns True on success."""
    return write_clipboard("")
