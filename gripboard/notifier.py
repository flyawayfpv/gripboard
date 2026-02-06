"""Notification system for scan results."""

import shutil
import subprocess
import sys

from gripboard.scanner import Finding, ScanResult, Severity

# ANSI color codes
_COLORS = {
    Severity.SAFE: "\033[32m",      # green
    Severity.LOW: "\033[33m",       # yellow
    Severity.MEDIUM: "\033[33m",    # yellow
    Severity.HIGH: "\033[31m",      # red
    Severity.CRITICAL: "\033[1;31m",  # bold red
}
_RESET = "\033[0m"

_SEV_ORDER = {
    Severity.SAFE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _sev_from_str(s: str) -> Severity:
    try:
        return Severity(s.lower())
    except ValueError:
        return Severity.LOW


class Notifier:
    """Sends notifications about scan findings."""

    def __init__(self, mode: str = "both", min_severity: str = "low"):
        self.mode = mode
        self.min_severity = _sev_from_str(min_severity)

    def notify(self, result: ScanResult) -> None:
        """Send notification if the result meets the minimum severity threshold."""
        if result.is_clean:
            return
        if _SEV_ORDER[result.severity] < _SEV_ORDER[self.min_severity]:
            return

        if self.mode in ("terminal", "both"):
            self._notify_terminal(result)
        if self.mode in ("desktop", "both"):
            self._notify_desktop(result)

    def _notify_terminal(self, result: ScanResult) -> None:
        sev = result.severity
        color = _COLORS.get(sev, "")

        preview = result.content[:80]
        if len(result.content) > 80:
            preview += "..."

        print(
            f"\n{color}[GRIPBOARD {sev.value.upper()}]{_RESET} "
            f"Suspicious clipboard content detected!",
            file=sys.stderr,
        )
        print(f"  Content preview: {preview!r}", file=sys.stderr)
        print(f"  Findings ({len(result.findings)}):", file=sys.stderr)

        for f in result.findings[:10]:  # cap output at 10 findings
            _print_finding(f)

        if len(result.findings) > 10:
            print(
                f"  ... and {len(result.findings) - 10} more findings",
                file=sys.stderr,
            )
        print(file=sys.stderr)

    def _notify_desktop(self, result: ScanResult) -> None:
        if not shutil.which("notify-send"):
            return

        sev = result.severity
        urgency = "critical" if sev in (Severity.HIGH, Severity.CRITICAL) else "normal"

        summary = f"Gripboard: {sev.value.upper()} alert"
        body = f"{len(result.findings)} suspicious character(s) detected in clipboard."

        if result.findings:
            top = result.findings[0]
            body += f"\nTop finding: {top.description}"

        try:
            subprocess.run(
                [
                    "notify-send",
                    "--urgency", urgency,
                    "--app-name", "Gripboard",
                    summary,
                    body,
                ],
                timeout=5,
                check=False,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass


def _print_finding(f: Finding) -> None:
    color = _COLORS.get(f.severity, "")
    print(
        f"    {color}[{f.severity.value.upper()}]{_RESET} "
        f"pos {f.position}: {f.codepoint} - {f.description}",
        file=sys.stderr,
    )
