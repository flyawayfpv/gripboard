"""Tests for the audit logging system."""

import tempfile
from pathlib import Path

from gripboard.audit import AuditLog
from gripboard.scanner import ScanResult, Scanner
from gripboard.scoring import ScoreBreakdown, compute_score


class TestAuditLog:
    def setup_method(self):
        self._tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self._tmpdir) / "test_audit.db"
        self.log = AuditLog(db_path=self.db_path)

    def teardown_method(self):
        self.log.close()

    def test_log_clean_scan(self):
        result = ScanResult(content="echo hello", findings=[])
        score = compute_score(result)
        row_id = self.log.log_scan(result, score=score)
        assert row_id == 1

    def test_log_and_query(self):
        scanner = Scanner()
        result = scanner.scan("\u200Bhello")
        score = compute_score(result)
        self.log.log_scan(result, score=score, app_class="kitty", profile_name="terminal")

        entries = self.log.query(limit=10)
        assert len(entries) == 1
        e = entries[0]
        assert e.app_class == "kitty"
        assert e.profile_name == "terminal"
        assert e.findings_count > 0
        assert e.score > 0

    def test_query_by_severity(self):
        scanner = Scanner()

        result1 = scanner.scan("hello")
        self.log.log_scan(result1, score=compute_score(result1))

        result2 = scanner.scan("\u200Bhello")
        self.log.log_scan(result2, score=compute_score(result2))

        high_entries = self.log.query(severity="high")
        assert len(high_entries) == 1

    def test_log_action(self):
        result = ScanResult(content="test", findings=[])
        self.log.log_scan(result, score=compute_score(result), action="block")
        entries = self.log.query()
        assert entries[0].action == "block"

    def test_stats(self):
        scanner = Scanner()
        for text in ["hello", "\u200Bbad", "\u202Eworse"]:
            result = scanner.scan(text)
            self.log.log_scan(result, score=compute_score(result))

        stats = self.log.stats()
        assert stats["total_scans"] == 3
        assert isinstance(stats["by_severity"], dict)
        assert isinstance(stats["by_action"], dict)

    def test_export_json(self):
        import json
        result = ScanResult(content="test", findings=[])
        self.log.log_scan(result, score=compute_score(result))

        exported = self.log.export_json()
        data = json.loads(exported)
        assert len(data) == 1
        assert "timestamp" in data[0]

    def test_multiple_entries_ordered(self):
        for i in range(5):
            result = ScanResult(content=f"entry {i}", findings=[])
            self.log.log_scan(result, score=compute_score(result))

        entries = self.log.query(limit=3)
        assert len(entries) == 3
        # Should be newest first
        assert entries[0].id > entries[1].id
