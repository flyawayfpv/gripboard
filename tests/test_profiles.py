"""Tests for per-application profiles."""

from gripboard.profiles import AppProfile, BUILTIN_PROFILES, resolve_profile


class TestResolveProfile:
    def test_no_profiles(self):
        assert resolve_profile("kitty", []) is None

    def test_no_app_class(self):
        assert resolve_profile(None, BUILTIN_PROFILES) is None

    def test_match_terminal(self):
        profile = resolve_profile("kitty", BUILTIN_PROFILES)
        assert profile is not None
        assert profile.name == "terminal"
        assert profile.check_ascii is True
        assert profile.confirm_paste is True

    def test_match_browser(self):
        profile = resolve_profile("firefox", BUILTIN_PROFILES)
        assert profile is not None
        assert profile.name == "browser"
        assert profile.check_ascii is False
        assert profile.confirm_paste is False

    def test_match_editor(self):
        profile = resolve_profile("code", BUILTIN_PROFILES)
        assert profile is not None
        assert profile.name == "editor"

    def test_case_insensitive(self):
        profile = resolve_profile("Firefox", BUILTIN_PROFILES)
        assert profile is not None
        assert profile.name == "browser"

    def test_substring_match(self):
        profile = resolve_profile("google-chrome-stable", BUILTIN_PROFILES)
        assert profile is not None
        assert profile.name == "browser"

    def test_unknown_app(self):
        profile = resolve_profile("my-custom-app", BUILTIN_PROFILES)
        assert profile is None

    def test_custom_profile_priority(self):
        custom = AppProfile(
            name="my-strict-browser",
            match=["firefox"],
            check_ascii=True,
            confirm_paste=True,
        )
        # Custom profiles checked first
        profile = resolve_profile("firefox", [custom] + BUILTIN_PROFILES)
        assert profile is not None
        assert profile.name == "my-strict-browser"
        assert profile.check_ascii is True

    def test_alacritty(self):
        profile = resolve_profile("Alacritty", BUILTIN_PROFILES)
        assert profile is not None
        assert profile.name == "terminal"

    def test_konsole(self):
        profile = resolve_profile("konsole", BUILTIN_PROFILES)
        assert profile is not None
        assert profile.name == "terminal"
