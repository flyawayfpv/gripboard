"""Command-line interface for Gripboard."""

import argparse
import json
import sys
import threading
from pathlib import Path

from gripboard import __version__
from gripboard.audit import AuditLog
from gripboard.config import GripboardConfig, init_config, load_config
from gripboard.monitor import watch_clipboard
from gripboard.notifier import Notifier
from gripboard.profiles import BUILTIN_PROFILES, get_active_window_class, resolve_profile
from gripboard.rules import Ruleset, load_rules_from_dir, load_rules_from_toml
from gripboard.sanitizer import clear_clipboard, sanitize, write_clipboard
from gripboard.scanner import Scanner, Severity
from gripboard.scoring import ScoreBreakdown, full_analysis
from gripboard.sync import COMMUNITY_RULES_PATH

# Built-in rules directory
_BUILTIN_RULES_DIR = Path(__file__).parent.parent / "data" / "rules"
# User rules directory
_USER_RULES_DIR = Path("~/.config/gripboard/rules").expanduser()


def _load_ruleset() -> Ruleset:
    """Load built-in rules, community rules, then user rules on top."""
    ruleset = load_rules_from_dir(_BUILTIN_RULES_DIR)
    # Community rules (synced from API)
    if COMMUNITY_RULES_PATH.exists():
        try:
            community = load_rules_from_toml(COMMUNITY_RULES_PATH)
            ruleset.merge(community)
        except Exception:
            pass
    # User rules take highest priority
    user_rules = load_rules_from_dir(_USER_RULES_DIR)
    ruleset.merge(user_rules)
    return ruleset


def _build_scanner(config: GripboardConfig, profile=None) -> Scanner:
    sc = config.scanner
    check_ascii = sc.check_ascii
    check_homoglyphs = sc.check_homoglyphs
    check_invisible = sc.check_invisible
    check_bidi = sc.check_bidi
    allowed = set(sc.allowed_codepoints)

    # Apply profile overrides
    if profile is not None:
        if profile.check_ascii is not None:
            check_ascii = profile.check_ascii
        if profile.check_homoglyphs is not None:
            check_homoglyphs = profile.check_homoglyphs
        if profile.check_invisible is not None:
            check_invisible = profile.check_invisible
        if profile.check_bidi is not None:
            check_bidi = profile.check_bidi
        allowed |= profile.allowed_codepoints

    return Scanner(
        check_ascii=check_ascii,
        check_homoglyph=check_homoglyphs,
        check_invis=check_invisible,
        check_bidi_attacks=check_bidi,
        allowed_codepoints=allowed,
    )


def _build_notifier(config: GripboardConfig) -> Notifier:
    return Notifier(
        mode=config.notifications.mode,
        min_severity=config.notifications.min_severity,
    )


def _print_score(breakdown: ScoreBreakdown) -> None:
    """Print the heuristic score breakdown to stderr."""
    color = {
        Severity.SAFE: "\033[32m",
        Severity.LOW: "\033[33m",
        Severity.MEDIUM: "\033[33m",
        Severity.HIGH: "\033[31m",
        Severity.CRITICAL: "\033[1;31m",
    }.get(breakdown.severity, "")
    reset = "\033[0m"

    print(
        f"  {color}Risk Score: {breakdown.total_score}/100 "
        f"({breakdown.severity.value.upper()}){reset}",
        file=sys.stderr,
    )
    for detail in breakdown.details:
        print(f"    - {detail}", file=sys.stderr)


def cmd_watch(args: argparse.Namespace) -> None:
    """Run the clipboard monitoring daemon (terminal-only, no GUI)."""
    config = load_config(args.config)
    notifier = _build_notifier(config)
    ruleset = _load_ruleset()
    audit = AuditLog()
    all_profiles = config.profiles + BUILTIN_PROFILES

    print(f"Gripboard v{__version__} - watching clipboard...", file=sys.stderr)
    print(f"Loaded {len(ruleset.rules)} detection rules.", file=sys.stderr)
    print("Press Ctrl+C to stop.\n", file=sys.stderr)

    def on_clipboard_change(content: str) -> None:
        profile = None
        app_class = None
        if config.monitor.use_profiles:
            app_class = get_active_window_class()
            profile = resolve_profile(app_class, all_profiles)

        scanner = _build_scanner(config, profile)
        result = scanner.scan(content)

        # Run full analysis (rules + shell parser + scoring)
        breakdown = full_analysis(content, result, ruleset)

        # Merge rule findings into the scan result for notification
        rule_findings = ruleset.evaluate(content)
        result.findings.extend(rule_findings)

        # Use the score-derived severity if higher
        if breakdown.severity.value != "safe":
            notifier.notify(result)
            _print_score(breakdown)

        # Audit log
        audit.log_scan(
            result,
            score=breakdown,
            app_class=app_class,
            profile_name=profile.name if profile else None,
        )

    try:
        watch_clipboard(on_clipboard_change, config.monitor.poll_interval)
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nGripboard stopped.", file=sys.stderr)
        audit.close()


def cmd_gui(args: argparse.Namespace) -> None:
    """Run with system tray icon and confirmation dialogs."""
    try:
        import gi
        gi.require_version("Gtk", "3.0")
        from gi.repository import GLib
    except (ImportError, ValueError):
        print("Error: GTK3 not available. Install PyGObject.", file=sys.stderr)
        print("Falling back to terminal mode.", file=sys.stderr)
        cmd_watch(args)
        return

    from gripboard.dialog import PasteAction, show_confirmation_dialog
    from gripboard.tray import TrayApp

    config = load_config(args.config)
    notifier = _build_notifier(config)
    ruleset = _load_ruleset()
    audit = AuditLog()
    all_profiles = config.profiles + BUILTIN_PROFILES

    tray = TrayApp()

    def on_clipboard_change(content: str) -> None:
        if not tray.is_monitoring:
            return

        profile = None
        app_class = None
        if config.monitor.use_profiles:
            app_class = get_active_window_class()
            profile = resolve_profile(app_class, all_profiles)

        scanner = _build_scanner(config, profile)
        result = scanner.scan(content)

        # Run full analysis
        breakdown = full_analysis(content, result, ruleset)

        # Merge rule findings
        rule_findings = ruleset.evaluate(content)
        result.findings.extend(rule_findings)

        if result.is_clean and breakdown.total_score == 0:
            return

        tray.push_result(result)
        notifier.notify(result)

        # Show confirmation dialog if enabled
        should_confirm = config.monitor.confirm_paste
        if profile is not None:
            should_confirm = profile.confirm_paste

        effective_severity = breakdown.severity
        if should_confirm and effective_severity in (Severity.HIGH, Severity.CRITICAL):
            sanitized_text = sanitize(result)

            def show_dialog():
                action_taken = show_confirmation_dialog(result, sanitized_text)
                if action_taken == PasteAction.SANITIZE:
                    write_clipboard(sanitized_text)
                elif action_taken == PasteAction.BLOCK:
                    clear_clipboard()

                audit.log_scan(
                    result,
                    score=breakdown,
                    action=action_taken,
                    app_class=app_class,
                    profile_name=profile.name if profile else None,
                )

            GLib.idle_add(show_dialog)
        else:
            audit.log_scan(
                result,
                score=breakdown,
                app_class=app_class,
                profile_name=profile.name if profile else None,
            )

    # Run clipboard monitor in a background thread
    monitor_thread = threading.Thread(
        target=watch_clipboard,
        args=(on_clipboard_change, config.monitor.poll_interval),
        daemon=True,
    )
    monitor_thread.start()

    print(f"Gripboard v{__version__} - GUI mode active", file=sys.stderr)
    print(f"Loaded {len(ruleset.rules)} detection rules.", file=sys.stderr)

    try:
        tray.run()
    except KeyboardInterrupt:
        tray.quit()
        audit.close()


def cmd_scan(args: argparse.Namespace) -> None:
    """Scan text from stdin or a provided string."""
    config = load_config(args.config)
    scanner = _build_scanner(config)
    ruleset = _load_ruleset()

    if args.text:
        content = args.text
    else:
        content = sys.stdin.read()

    result = scanner.scan(content)

    # Run full analysis
    breakdown = full_analysis(content, result, ruleset)

    # Merge rule findings into result
    rule_findings = ruleset.evaluate(content)
    result.findings.extend(rule_findings)

    if result.is_clean and breakdown.total_score == 0:
        print("Clean - no suspicious characters or patterns found.")
        sys.exit(0)

    notifier = _build_notifier(config)
    notifier._notify_terminal(result)
    _print_score(breakdown)

    # Show sanitized version
    sanitized_text = sanitize(result)
    if sanitized_text != content:
        print(f"  Sanitized: {sanitized_text!r}", file=sys.stderr)

    # Exit code reflects severity
    sev_codes = {
        Severity.SAFE: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }
    exit_sev = max(result.severity, breakdown.severity,
                   key=lambda s: sev_codes.get(s, 0))
    sys.exit(sev_codes.get(exit_sev, 1))


def cmd_log(args: argparse.Namespace) -> None:
    """Query the audit log."""
    audit = AuditLog()

    if args.stats:
        stats = audit.stats()
        print(json.dumps(stats, indent=2))
        audit.close()
        return

    if args.export:
        print(audit.export_json(limit=args.limit))
        audit.close()
        return

    entries = audit.query(
        limit=args.limit,
        severity=args.severity,
    )

    if not entries:
        print("No audit log entries found.")
        audit.close()
        return

    for e in entries:
        sev_color = {
            "low": "\033[33m",
            "medium": "\033[33m",
            "high": "\033[31m",
            "critical": "\033[1;31m",
        }.get(e.severity, "\033[32m")
        reset = "\033[0m"

        ts = e.timestamp[:19].replace("T", " ")
        preview = e.content_preview[:60].replace("\n", " ")
        if len(e.content_preview) > 60:
            preview += "..."

        app = e.app_class or "unknown"
        action = e.action if e.action != "none" else ""

        print(
            f"{ts}  {sev_color}{e.severity:>8}{reset}  "
            f"score={e.score:>3}  findings={e.findings_count}  "
            f"app={app}  {action}",
        )
        print(f"  {preview!r}")

    audit.close()


def cmd_init(args: argparse.Namespace) -> None:
    """Initialize a default configuration file."""
    path = init_config(args.config)
    print(f"Config created at: {path}")


def cmd_sync(args: argparse.Namespace) -> None:
    """Sync community rules and optionally submit telemetry."""
    from gripboard.sync import get_last_sync, submit_telemetry, sync_rules

    config = load_config(args.config)
    api_url = config.community.api_url

    last = get_last_sync()
    if last:
        print(f"Last sync: {last}")

    print(f"Syncing rules from {api_url}...")
    result = sync_rules(api_url=api_url)

    if result["status"] == "ok":
        print(f"Synced {result['rules_synced']} community rules.")
        print(f"Saved to: {result['saved_to']}")
    else:
        print(f"Sync failed: {result.get('message', 'unknown error')}", file=sys.stderr)

    # Submit telemetry if opted in
    if config.community.telemetry or getattr(args, "telemetry", False):
        print("Submitting anonymized telemetry...")
        tel_result = submit_telemetry(api_url=api_url)
        if tel_result.get("status") == "received":
            print("Telemetry submitted.")
        else:
            print(f"Telemetry failed: {tel_result.get('message', 'unknown')}", file=sys.stderr)


def cmd_serve(args: argparse.Namespace) -> None:
    """Start the Gripboard API server."""
    try:
        import uvicorn
    except ImportError:
        print("Error: uvicorn not installed. Run: pip install uvicorn[standard]", file=sys.stderr)
        sys.exit(1)

    print(f"Starting Gripboard API server on {args.host}:{args.port}...")
    uvicorn.run(
        "gripboard.server.app:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


def cmd_install(args: argparse.Namespace) -> None:
    """Install autostart and systemd service for the current user."""
    import shutil
    data_dir = Path(__file__).parent.parent / "data"

    # Ensure config exists
    init_config(args.config)

    # Install XDG autostart entry
    autostart_dir = Path.home() / ".config" / "autostart"
    autostart_dir.mkdir(parents=True, exist_ok=True)
    desktop_src = data_dir / "gripboard.desktop"
    desktop_dst = autostart_dir / "gripboard.desktop"
    if desktop_src.exists():
        shutil.copy2(desktop_src, desktop_dst)
        print(f"Autostart entry: {desktop_dst}")

    # Install systemd user service
    systemd_dir = Path.home() / ".config" / "systemd" / "user"
    systemd_dir.mkdir(parents=True, exist_ok=True)
    service_src = data_dir / "gripboard.service"
    service_dst = systemd_dir / "gripboard.service"
    if service_src.exists():
        shutil.copy2(service_src, service_dst)
        print(f"Systemd service: {service_dst}")
        print("  Enable with: systemctl --user enable --now gripboard")

    print("Installation complete.")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="gripboard",
        description="Clipboard scanner that detects malicious Unicode content",
    )
    parser.add_argument(
        "-V", "--version", action="version", version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "-c", "--config", type=Path, default=None,
        help="Path to config file (default: ~/.config/gripboard/config.toml)",
    )

    subparsers = parser.add_subparsers(dest="command")

    # watch (terminal-only)
    watch_parser = subparsers.add_parser(
        "watch", help="Monitor clipboard in terminal mode",
    )
    watch_parser.set_defaults(func=cmd_watch)

    # gui (tray icon + dialogs)
    gui_parser = subparsers.add_parser(
        "gui", help="Run with system tray icon and confirmation dialogs",
    )
    gui_parser.set_defaults(func=cmd_gui)

    # scan
    scan_parser = subparsers.add_parser(
        "scan", help="Scan text from stdin or argument",
    )
    scan_parser.add_argument(
        "text", nargs="?", default=None,
        help="Text to scan (reads from stdin if omitted)",
    )
    scan_parser.set_defaults(func=cmd_scan)

    # log
    log_parser = subparsers.add_parser(
        "log", help="Query the audit log",
    )
    log_parser.add_argument(
        "-n", "--limit", type=int, default=20,
        help="Number of entries to show (default: 20)",
    )
    log_parser.add_argument(
        "-s", "--severity", default=None,
        help="Filter by severity (low, medium, high, critical)",
    )
    log_parser.add_argument(
        "--stats", action="store_true",
        help="Show aggregate statistics",
    )
    log_parser.add_argument(
        "--export", action="store_true",
        help="Export full log as JSON",
    )
    log_parser.set_defaults(func=cmd_log)

    # init
    init_parser = subparsers.add_parser(
        "init", help="Create default config file",
    )
    init_parser.set_defaults(func=cmd_init)

    # sync
    sync_parser = subparsers.add_parser(
        "sync", help="Sync community rules from the API",
    )
    sync_parser.add_argument(
        "--telemetry", action="store_true",
        help="Also submit anonymized telemetry",
    )
    sync_parser.set_defaults(func=cmd_sync)

    # serve
    serve_parser = subparsers.add_parser(
        "serve", help="Start the Gripboard API server",
    )
    serve_parser.add_argument(
        "--host", default="0.0.0.0",
        help="Bind address (default: 0.0.0.0)",
    )
    serve_parser.add_argument(
        "--port", type=int, default=8000,
        help="Port (default: 8000)",
    )
    serve_parser.add_argument(
        "--reload", action="store_true",
        help="Enable auto-reload for development",
    )
    serve_parser.set_defaults(func=cmd_serve)

    # install
    install_parser = subparsers.add_parser(
        "install", help="Install autostart and systemd user service",
    )
    install_parser.set_defaults(func=cmd_install)

    args = parser.parse_args()
    if not args.command:
        # Default to GUI mode
        args.func = cmd_gui
        cmd_gui(args)
        return

    args.func(args)
