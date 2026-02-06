"""Shell command parser — structural analysis of clipboard content as shell commands."""

import re
import shlex
from dataclasses import dataclass, field
from enum import Enum


class CommandRisk(Enum):
    SAFE = "safe"
    INFO = "info"
    CAUTION = "caution"
    DANGEROUS = "dangerous"
    CRITICAL = "critical"


@dataclass
class CommandAnalysis:
    raw: str
    risk: CommandRisk = CommandRisk.SAFE
    reasons: list[str] = field(default_factory=list)
    commands_found: list[str] = field(default_factory=list)
    has_pipe: bool = False
    has_redirect: bool = False
    has_sudo: bool = False
    has_backgrounding: bool = False


# Commands categorized by risk
DESTRUCTIVE_COMMANDS = {
    "rm", "rmdir", "shred", "wipefs",
    "dd", "mkfs", "mkswap", "fdisk", "parted",
    "kill", "killall", "pkill",
}

PRIVILEGE_COMMANDS = {
    "sudo", "su", "doas", "pkexec",
}

NETWORK_COMMANDS = {
    "curl", "wget", "nc", "ncat", "netcat",
    "ssh", "scp", "sftp", "rsync",
    "ftp", "telnet",
}

INTERPRETERS = {
    "sh", "bash", "zsh", "fish", "dash",
    "python", "python3", "python2",
    "perl", "ruby", "node", "php",
}

PERSISTENCE_COMMANDS = {
    "crontab", "at", "systemctl",
}

EXFIL_TARGETS = re.compile(
    r"/etc/(shadow|passwd|hosts)|\.ssh/(id_rsa|id_ed25519|authorized_keys)"
    r"|\.bashrc|\.bash_profile|\.gnupg"
)

PIPE_TO_SHELL_RE = re.compile(
    r"(curl|wget)\s+.*\|\s*(sudo\s+)?(ba)?sh\b", re.IGNORECASE
)

REDIRECT_PATTERNS = re.compile(r"[12]?>>?|&>>?")


def analyze_content(content: str) -> list[CommandAnalysis]:
    """Analyze clipboard content as potential shell commands.

    Splits on newlines and semicolons to identify individual commands,
    then analyzes each for risk factors.
    """
    results = []

    # Split content into logical lines
    lines = content.strip().splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        analysis = _analyze_line(line)
        results.append(analysis)

    return results


def _analyze_line(line: str) -> CommandAnalysis:
    """Analyze a single line of shell input."""
    analysis = CommandAnalysis(raw=line)

    # Check structural features
    analysis.has_pipe = "|" in line
    analysis.has_redirect = bool(REDIRECT_PATTERNS.search(line))
    analysis.has_backgrounding = line.rstrip().endswith("&")

    # Extract command names from the line
    commands = _extract_commands(line)
    analysis.commands_found = commands

    # Check for sudo
    if PRIVILEGE_COMMANDS & set(commands):
        analysis.has_sudo = True
        analysis.reasons.append(f"Uses privilege escalation: {PRIVILEGE_COMMANDS & set(commands)}")
        _elevate(analysis, CommandRisk.CAUTION)

    # Check pipe-to-shell pattern
    if PIPE_TO_SHELL_RE.search(line):
        analysis.reasons.append("Pipe-to-shell: downloads and executes remote code")
        _elevate(analysis, CommandRisk.CRITICAL)

    # Check individual commands
    for cmd in commands:
        if cmd in DESTRUCTIVE_COMMANDS:
            analysis.reasons.append(f"Destructive command: {cmd}")
            _elevate(analysis, CommandRisk.DANGEROUS)

        if cmd in INTERPRETERS and analysis.has_pipe:
            analysis.reasons.append(f"Piping into interpreter: {cmd}")
            _elevate(analysis, CommandRisk.DANGEROUS)

        if cmd in NETWORK_COMMANDS:
            analysis.reasons.append(f"Network command: {cmd}")
            _elevate(analysis, CommandRisk.CAUTION)

        if cmd in PERSISTENCE_COMMANDS:
            analysis.reasons.append(f"Persistence mechanism: {cmd}")
            _elevate(analysis, CommandRisk.CAUTION)

    # Check for sensitive file access
    if EXFIL_TARGETS.search(line):
        analysis.reasons.append("Accesses sensitive files")
        _elevate(analysis, CommandRisk.DANGEROUS)

    # Combined risk escalation
    if analysis.has_sudo and analysis.risk in (CommandRisk.DANGEROUS, CommandRisk.CRITICAL):
        analysis.reasons.append("Destructive/network operation with elevated privileges")
        _elevate(analysis, CommandRisk.CRITICAL)

    if analysis.has_pipe and analysis.has_redirect and len(commands) >= 3:
        analysis.reasons.append("Complex pipeline with redirection")
        _elevate(analysis, CommandRisk.CAUTION)

    return analysis


def _extract_commands(line: str) -> list[str]:
    """Extract command names from a shell line, handling pipes and semicolons."""
    commands = []

    # Split on pipes and semicolons to get individual commands
    segments = re.split(r'[|;]|&&|\|\|', line)

    for segment in segments:
        segment = segment.strip()
        if not segment:
            continue

        # Try to use shlex to parse properly
        try:
            tokens = shlex.split(segment)
        except ValueError:
            # Malformed quoting — fall back to simple split
            tokens = segment.split()

        if not tokens:
            continue

        # Skip env vars, sudo prefix, and command substitutions
        cmd = tokens[0]
        # Strip leading env assignments like KEY=val
        while "=" in cmd and not cmd.startswith("="):
            tokens = tokens[1:]
            if not tokens:
                break
            cmd = tokens[0]

        if not tokens:
            continue

        # Skip sudo/doas to find the real command
        i = 0
        while i < len(tokens) and tokens[i] in PRIVILEGE_COMMANDS:
            commands.append(tokens[i])
            i += 1
            # Skip sudo flags
            while i < len(tokens) and tokens[i].startswith("-"):
                i += 1

        if i < len(tokens):
            real_cmd = tokens[i].split("/")[-1]  # basename
            commands.append(real_cmd)

    return commands


_RISK_ORDER = {
    CommandRisk.SAFE: 0,
    CommandRisk.INFO: 1,
    CommandRisk.CAUTION: 2,
    CommandRisk.DANGEROUS: 3,
    CommandRisk.CRITICAL: 4,
}


def _elevate(analysis: CommandAnalysis, to: CommandRisk) -> None:
    """Elevate risk level only if the new level is higher."""
    if _RISK_ORDER[to] > _RISK_ORDER[analysis.risk]:
        analysis.risk = to


def overall_risk(analyses: list[CommandAnalysis]) -> CommandRisk:
    """Return the highest risk across all analyzed commands."""
    if not analyses:
        return CommandRisk.SAFE
    return max(analyses, key=lambda a: _RISK_ORDER[a.risk]).risk
