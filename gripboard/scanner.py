"""Core scanning engine for detecting malicious Unicode content."""

import unicodedata
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    rule: str
    description: str
    severity: Severity
    position: int  # character offset
    char: str
    codepoint: str  # e.g. "U+200B"


@dataclass
class ScanResult:
    content: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def severity(self) -> Severity:
        if not self.findings:
            return Severity.SAFE
        return max(self.findings, key=lambda f: _SEV_ORDER[f.severity]).severity

    @property
    def is_clean(self) -> bool:
        return len(self.findings) == 0


_SEV_ORDER = {
    Severity.SAFE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


# ---------------------------------------------------------------------------
# Invisible / zero-width characters
# ---------------------------------------------------------------------------

INVISIBLE_CHARS: dict[int, str] = {
    0x200B: "Zero Width Space",
    0x200C: "Zero Width Non-Joiner",
    0x200D: "Zero Width Joiner",
    0x2060: "Word Joiner",
    0xFEFF: "Zero Width No-Break Space (BOM)",
    0x00AD: "Soft Hyphen",
    0x034F: "Combining Grapheme Joiner",
    0x061C: "Arabic Letter Mark",
    0x115F: "Hangul Choseong Filler",
    0x1160: "Hangul Jungseong Filler",
    0x17B4: "Khmer Vowel Inherent Aq",
    0x17B5: "Khmer Vowel Inherent Aa",
    0x180E: "Mongolian Vowel Separator",
    0x2000: "En Quad",
    0x2001: "Em Quad",
    0x2002: "En Space",
    0x2003: "Em Space",
    0x2004: "Three-Per-Em Space",
    0x2005: "Four-Per-Em Space",
    0x2006: "Six-Per-Em Space",
    0x2007: "Figure Space",
    0x2008: "Punctuation Space",
    0x2009: "Thin Space",
    0x200A: "Hair Space",
    0x2028: "Line Separator",
    0x2029: "Paragraph Separator",
    0x202F: "Narrow No-Break Space",
    0x205F: "Medium Mathematical Space",
    0x3000: "Ideographic Space",
    0x3164: "Hangul Filler",
    0xFFA0: "Halfwidth Hangul Filler",
}


def check_invisible(content: str) -> list[Finding]:
    """Detect invisible or zero-width characters."""
    findings = []
    for i, ch in enumerate(content):
        cp = ord(ch)
        if cp in INVISIBLE_CHARS:
            findings.append(Finding(
                rule="invisible-char",
                description=f"Invisible character: {INVISIBLE_CHARS[cp]}",
                severity=Severity.HIGH,
                position=i,
                char=ch,
                codepoint=f"U+{cp:04X}",
            ))
    return findings


# ---------------------------------------------------------------------------
# Bidirectional / Trojan Source attacks
# ---------------------------------------------------------------------------

BIDI_CODEPOINTS: dict[int, str] = {
    0x202A: "Left-to-Right Embedding",
    0x202B: "Right-to-Left Embedding",
    0x202C: "Pop Directional Formatting",
    0x202D: "Left-to-Right Override",
    0x202E: "Right-to-Left Override",
    0x2066: "Left-to-Right Isolate",
    0x2067: "Right-to-Left Isolate",
    0x2068: "First Strong Isolate",
    0x2069: "Pop Directional Isolate",
}


def check_bidi(content: str) -> list[Finding]:
    """Detect bidirectional control characters (Trojan Source attacks)."""
    findings = []
    for i, ch in enumerate(content):
        cp = ord(ch)
        if cp in BIDI_CODEPOINTS:
            findings.append(Finding(
                rule="bidi-control",
                description=f"Bidi control character: {BIDI_CODEPOINTS[cp]}",
                severity=Severity.CRITICAL,
                position=i,
                char=ch,
                codepoint=f"U+{cp:04X}",
            ))
    return findings


# ---------------------------------------------------------------------------
# Non-ASCII detection (outside printable English range)
# ---------------------------------------------------------------------------

def check_non_ascii(content: str) -> list[Finding]:
    """Flag characters outside the printable ASCII range (0x20-0x7E) plus common whitespace."""
    allowed_whitespace = {0x09, 0x0A, 0x0D}  # tab, newline, carriage return
    findings = []
    for i, ch in enumerate(content):
        cp = ord(ch)
        if cp in allowed_whitespace:
            continue
        if cp < 0x20 or cp > 0x7E:
            name = unicodedata.name(ch, f"UNKNOWN (U+{cp:04X})")
            findings.append(Finding(
                rule="non-ascii",
                description=f"Non-ASCII character: {name}",
                severity=Severity.LOW,
                position=i,
                char=ch,
                codepoint=f"U+{cp:04X}",
            ))
    return findings


# ---------------------------------------------------------------------------
# Homoglyph detection — characters that look like ASCII but aren't
# ---------------------------------------------------------------------------

# Common confusable mappings: non-ASCII char -> ASCII char it imitates.
# This is a curated subset; the full Unicode confusables list has thousands.
CONFUSABLES: dict[int, str] = {
    # Cyrillic -> Latin lookalikes
    0x0410: "A",  # А -> A
    0x0430: "a",  # а -> a
    0x0412: "B",  # В -> B
    0x0421: "C",  # С -> C
    0x0441: "c",  # с -> c
    0x0415: "E",  # Е -> E
    0x0435: "e",  # е -> e
    0x041D: "H",  # Н -> H
    0x041A: "K",  # К -> K
    0x043A: "k",  # к -> k (sort of)
    0x041C: "M",  # М -> M
    0x041E: "O",  # О -> O
    0x043E: "o",  # о -> o
    0x0420: "P",  # Р -> P
    0x0440: "p",  # р -> p
    0x0422: "T",  # Т -> T
    0x0425: "X",  # Х -> X
    0x0445: "x",  # х -> x
    0x0443: "y",  # у -> y
    # Greek -> Latin lookalikes
    0x0391: "A",  # Α -> A
    0x03B1: "a",  # α -> a (close)
    0x0392: "B",  # Β -> B
    0x0395: "E",  # Ε -> E
    0x0397: "H",  # Η -> H
    0x0399: "I",  # Ι -> I
    0x039A: "K",  # Κ -> K
    0x039C: "M",  # Μ -> M
    0x039D: "N",  # Ν -> N
    0x039F: "O",  # Ο -> O
    0x03BF: "o",  # ο -> o
    0x03A1: "P",  # Ρ -> P
    0x03A4: "T",  # Τ -> T
    0x03A5: "Y",  # Υ -> Y
    0x03A7: "X",  # Χ -> X
    0x0396: "Z",  # Ζ -> Z
    # Fullwidth Latin
    0xFF21: "A",  # Ａ -> A
    0xFF22: "B",  # Ｂ -> B
    0xFF23: "C",  # Ｃ -> C
    0xFF24: "D",  # Ｄ -> D
    0xFF25: "E",  # Ｅ -> E
    0xFF41: "a",  # ａ -> a
    0xFF42: "b",  # ｂ -> b
    0xFF43: "c",  # ｃ -> c
    0xFF44: "d",  # ｄ -> d
    0xFF45: "e",  # ｅ -> e
    # Common symbol confusables
    0x2010: "-",  # Hyphen
    0x2011: "-",  # Non-breaking hyphen
    0x2012: "-",  # Figure dash
    0x2013: "-",  # En dash
    0x2014: "-",  # Em dash
    0x2018: "'",  # Left single quote
    0x2019: "'",  # Right single quote
    0x201C: '"',  # Left double quote
    0x201D: '"',  # Right double quote
    0xFF0F: "/",  # Fullwidth solidus
    0xFF3C: "\\", # Fullwidth reverse solidus
    0xFF5C: "|",  # Fullwidth vertical line
    0x2044: "/",  # Fraction slash
    0x2215: "/",  # Division slash
    0x29F8: "/",  # Big solidus
}


def check_homoglyphs(content: str) -> list[Finding]:
    """Detect characters that visually mimic ASCII characters."""
    findings = []
    for i, ch in enumerate(content):
        cp = ord(ch)
        if cp in CONFUSABLES:
            lookalike = CONFUSABLES[cp]
            name = unicodedata.name(ch, f"U+{cp:04X}")
            findings.append(Finding(
                rule="homoglyph",
                description=f"'{ch}' ({name}) looks like ASCII '{lookalike}'",
                severity=Severity.HIGH,
                position=i,
                char=ch,
                codepoint=f"U+{cp:04X}",
            ))
    return findings


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------

class Scanner:
    """Configurable clipboard content scanner."""

    def __init__(
        self,
        check_ascii: bool = True,
        check_homoglyph: bool = True,
        check_invis: bool = True,
        check_bidi_attacks: bool = True,
        allowed_codepoints: set[int] | None = None,
    ):
        self.check_ascii = check_ascii
        self.check_homoglyph = check_homoglyph
        self.check_invis = check_invis
        self.check_bidi_attacks = check_bidi_attacks
        self.allowed_codepoints = allowed_codepoints or set()

    def scan(self, content: str) -> ScanResult:
        """Run all enabled checks on the given content."""
        result = ScanResult(content=content)

        if self.check_invis:
            result.findings.extend(check_invisible(content))
        if self.check_bidi_attacks:
            result.findings.extend(check_bidi(content))
        if self.check_homoglyph:
            result.findings.extend(check_homoglyphs(content))
        if self.check_ascii:
            result.findings.extend(check_non_ascii(content))

        # Filter out user-allowed codepoints
        if self.allowed_codepoints:
            result.findings = [
                f for f in result.findings
                if ord(f.char) not in self.allowed_codepoints
            ]

        # Deduplicate: if a char was caught by both homoglyph and non-ascii,
        # keep only the higher-severity finding per position.
        result.findings = _deduplicate(result.findings)

        return result


def _deduplicate(findings: list[Finding]) -> list[Finding]:
    """Keep the highest-severity finding per character position."""
    by_pos: dict[int, Finding] = {}
    for f in findings:
        existing = by_pos.get(f.position)
        if existing is None or _SEV_ORDER[f.severity] > _SEV_ORDER[existing.severity]:
            by_pos[f.position] = f
    return sorted(by_pos.values(), key=lambda f: f.position)
