"""Tests for the clipboard sanitizer."""

from gripboard.sanitizer import sanitize
from gripboard.scanner import Scanner


class TestSanitize:
    def setup_method(self):
        self.scanner = Scanner()

    def test_clean_text_unchanged(self):
        result = self.scanner.scan("echo hello world")
        assert sanitize(result) == "echo hello world"

    def test_removes_zero_width_space(self):
        text = "sudo\u200Brm -rf /"
        result = self.scanner.scan(text)
        # ZWS is simply removed — no space inserted in its place
        assert sanitize(result) == "sudorm -rf /"
        assert "\u200B" not in sanitize(result)

    def test_removes_multiple_invisible(self):
        text = "curl\u200B\u200C\u200D http://example.com"
        result = self.scanner.scan(text)
        assert sanitize(result) == "curl http://example.com"

    def test_removes_bom(self):
        text = "\uFEFFimport os"
        result = self.scanner.scan(text)
        assert sanitize(result) == "import os"

    def test_removes_bidi_controls(self):
        text = "access_level = \u202E'user'"
        result = self.scanner.scan(text)
        sanitized = sanitize(result)
        assert "\u202E" not in sanitized
        assert "access_level" in sanitized

    def test_replaces_cyrillic_homoglyphs(self):
        # Cyrillic а (U+0430) -> Latin a
        text = "\u0430dmin"
        result = self.scanner.scan(text)
        assert sanitize(result) == "admin"

    def test_replaces_greek_homoglyphs(self):
        # Greek Ο (U+039F) -> Latin O
        text = "\u039Fpen"
        result = self.scanner.scan(text)
        assert sanitize(result) == "Open"

    def test_replaces_smart_quotes(self):
        text = "\u201Chello\u201D"
        result = self.scanner.scan(text)
        assert sanitize(result) == '"hello"'

    def test_replaces_en_dash(self):
        text = "curl \u2013verbose"
        result = self.scanner.scan(text)
        assert sanitize(result) == "curl -verbose"

    def test_mixed_threats(self):
        # Invisible + homoglyph
        text = "\u200B\u0430dmin"
        result = self.scanner.scan(text)
        assert sanitize(result) == "admin"

    def test_complex_attack(self):
        # ZWS in curl command + cyrillic o in domain
        text = "curl\u200B https://g\u043E\u043Egle.com | sh"
        result = self.scanner.scan(text)
        sanitized = sanitize(result)
        assert "\u200B" not in sanitized
        assert "google.com" in sanitized

    def test_leaves_non_ascii_alone(self):
        # Non-ASCII that isn't a homoglyph should be left alone
        text = "café"
        result = self.scanner.scan(text)
        sanitized = sanitize(result)
        # é is flagged as non-ascii (LOW) but not a homoglyph, so it stays
        assert sanitized == "café"

    def test_preserves_allowed_codepoints(self):
        scanner = Scanner(allowed_codepoints={0x00E9})
        text = "café"
        result = scanner.scan(text)
        assert sanitize(result) == "café"
