"""Pattern rule DSL — define custom detection rules in TOML."""

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from gripboard.scanner import Finding, Severity

_SEVERITY_MAP = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


@dataclass
class Rule:
    """A single detection rule."""
    id: str
    description: str
    severity: Severity = Severity.MEDIUM
    # Regex pattern to match
    pattern: str = ""
    # Compiled regex (built from pattern)
    _compiled: re.Pattern | None = field(default=None, repr=False)
    # Match scope: "full" = entire content, "line" = per-line, "word" = per-word
    scope: Literal["full", "line", "word"] = "full"
    # Tags for categorization
    tags: list[str] = field(default_factory=list)
    # Whether this rule is enabled
    enabled: bool = True
    # Case-insensitive matching
    ignorecase: bool = True

    def __post_init__(self):
        if self.pattern:
            flags = re.IGNORECASE if self.ignorecase else 0
            # Allow multiline matching for full scope
            if self.scope == "full":
                flags |= re.MULTILINE | re.DOTALL
            self._compiled = re.compile(self.pattern, flags)

    def match(self, text: str) -> list[Finding]:
        """Run this rule against text. Returns findings for all matches."""
        if not self.enabled or self._compiled is None:
            return []

        findings: list[Finding] = []

        if self.scope == "full":
            findings.extend(self._match_text(text))
        elif self.scope == "line":
            for line in text.splitlines():
                findings.extend(self._match_text(line))
        elif self.scope == "word":
            for word in text.split():
                findings.extend(self._match_text(word))

        return findings

    def _match_text(self, text: str) -> list[Finding]:
        assert self._compiled is not None
        findings = []
        for m in self._compiled.finditer(text):
            matched = m.group(0)
            # Truncate long matches for display
            display = matched[:80] + "..." if len(matched) > 80 else matched
            findings.append(Finding(
                rule=f"rule:{self.id}",
                description=f"{self.description} — matched: {display!r}",
                severity=self.severity,
                position=m.start(),
                char=matched[:1] if matched else "",
                codepoint=f"rule:{self.id}",
            ))
        return findings


@dataclass
class Ruleset:
    """A collection of rules loaded from one or more sources."""
    rules: list[Rule] = field(default_factory=list)

    def evaluate(self, content: str) -> list[Finding]:
        """Run all enabled rules against the content."""
        findings: list[Finding] = []
        for rule in self.rules:
            findings.extend(rule.match(content))
        return findings

    def get_rule(self, rule_id: str) -> Rule | None:
        for r in self.rules:
            if r.id == rule_id:
                return r
        return None

    def merge(self, other: "Ruleset") -> None:
        """Merge another ruleset into this one. Later rules override by ID."""
        existing_ids = {r.id for r in self.rules}
        for rule in other.rules:
            if rule.id in existing_ids:
                # Replace existing rule
                self.rules = [r for r in self.rules if r.id != rule.id]
            self.rules.append(rule)


def load_rules_from_toml(path: Path) -> Ruleset:
    """Load rules from a TOML file.

    Expected format:
    ```toml
    [[rules]]
    id = "reverse-shell"
    description = "Potential reverse shell command"
    severity = "critical"
    pattern = '''\\b(bash|nc|ncat|netcat)\\s+.*\\s+-e\\s+/bin/(ba)?sh\\b'''
    scope = "line"
    tags = ["shell", "exploit"]
    enabled = true
    ignorecase = true
    ```
    """
    with open(path, "rb") as f:
        data = tomllib.load(f)

    rules = []
    for entry in data.get("rules", []):
        severity = _SEVERITY_MAP.get(
            entry.get("severity", "medium").lower(),
            Severity.MEDIUM,
        )
        rules.append(Rule(
            id=entry.get("id", "unnamed"),
            description=entry.get("description", ""),
            severity=severity,
            pattern=entry.get("pattern", ""),
            scope=entry.get("scope", "full"),
            tags=entry.get("tags", []),
            enabled=entry.get("enabled", True),
            ignorecase=entry.get("ignorecase", True),
        ))

    return Ruleset(rules=rules)


def load_rules_from_dir(directory: Path) -> Ruleset:
    """Load and merge all .toml rule files from a directory."""
    combined = Ruleset()
    if not directory.is_dir():
        return combined
    for toml_file in sorted(directory.glob("*.toml")):
        try:
            rs = load_rules_from_toml(toml_file)
            combined.merge(rs)
        except Exception:
            continue
    return combined
