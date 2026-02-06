"""Heuristic scoring system — combines all analysis into a 0-100 risk score."""

from dataclasses import dataclass, field

from gripboard.rules import Ruleset
from gripboard.scanner import Finding, ScanResult, Severity
from gripboard.shellparser import CommandAnalysis, CommandRisk, analyze_content


# Weight per finding type and severity
_UNICODE_WEIGHTS = {
    Severity.LOW: 2,
    Severity.MEDIUM: 5,
    Severity.HIGH: 15,
    Severity.CRITICAL: 30,
}

_RULE_WEIGHTS = {
    Severity.LOW: 3,
    Severity.MEDIUM: 8,
    Severity.HIGH: 20,
    Severity.CRITICAL: 35,
}

_SHELL_WEIGHTS = {
    CommandRisk.SAFE: 0,
    CommandRisk.INFO: 1,
    CommandRisk.CAUTION: 8,
    CommandRisk.DANGEROUS: 25,
    CommandRisk.CRITICAL: 40,
}


def _score_to_severity(score: int) -> Severity:
    if score >= 70:
        return Severity.CRITICAL
    if score >= 45:
        return Severity.HIGH
    if score >= 20:
        return Severity.MEDIUM
    if score >= 5:
        return Severity.LOW
    return Severity.SAFE


@dataclass
class ScoreBreakdown:
    """Detailed breakdown of how the risk score was computed."""
    unicode_score: int = 0
    unicode_findings: int = 0
    rule_score: int = 0
    rule_matches: int = 0
    shell_score: int = 0
    shell_commands_analyzed: int = 0
    total_score: int = 0
    severity: Severity = Severity.SAFE
    details: list[str] = field(default_factory=list)


def compute_score(
    scan_result: ScanResult,
    rule_findings: list[Finding] | None = None,
    shell_analyses: list[CommandAnalysis] | None = None,
) -> ScoreBreakdown:
    """Compute a composite risk score from all analysis sources.

    Score ranges:
        0-4:   SAFE
        5-19:  LOW
        20-44: MEDIUM
        45-69: HIGH
        70-100: CRITICAL
    """
    breakdown = ScoreBreakdown()

    # 1. Unicode findings from scanner
    for f in scan_result.findings:
        weight = _UNICODE_WEIGHTS.get(f.severity, 2)
        breakdown.unicode_score += weight
        breakdown.unicode_findings += 1

    if breakdown.unicode_findings > 0:
        breakdown.details.append(
            f"Unicode: {breakdown.unicode_findings} finding(s) = {breakdown.unicode_score} pts"
        )

    # 2. Rule engine matches
    if rule_findings:
        for f in rule_findings:
            weight = _RULE_WEIGHTS.get(f.severity, 3)
            breakdown.rule_score += weight
            breakdown.rule_matches += 1

        breakdown.details.append(
            f"Rules: {breakdown.rule_matches} match(es) = {breakdown.rule_score} pts"
        )

    # 3. Shell command analysis
    if shell_analyses:
        breakdown.shell_commands_analyzed = len(shell_analyses)
        for a in shell_analyses:
            weight = _SHELL_WEIGHTS.get(a.risk, 0)
            breakdown.shell_score += weight

        if breakdown.shell_score > 0:
            breakdown.details.append(
                f"Shell: {breakdown.shell_commands_analyzed} command(s) = {breakdown.shell_score} pts"
            )

    # Composite score, capped at 100
    raw = breakdown.unicode_score + breakdown.rule_score + breakdown.shell_score
    breakdown.total_score = min(raw, 100)
    breakdown.severity = _score_to_severity(breakdown.total_score)

    return breakdown


def full_analysis(
    content: str,
    scan_result: ScanResult,
    ruleset: Ruleset | None = None,
    analyze_shell: bool = True,
) -> ScoreBreakdown:
    """Run all analysis layers and compute the final score."""
    rule_findings = None
    if ruleset:
        rule_findings = ruleset.evaluate(content)

    shell_analyses = None
    if analyze_shell:
        shell_analyses = analyze_content(content)

    return compute_score(
        scan_result,
        rule_findings=rule_findings,
        shell_analyses=shell_analyses,
    )
