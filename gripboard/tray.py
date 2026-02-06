"""System tray icon using Ayatana AppIndicator + GTK3."""

import threading

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("AyatanaAppIndicator3", "0.1")
gi.require_version("Notify", "0.7")

from gi.repository import AyatanaAppIndicator3 as AppIndicator3
from gi.repository import GLib, Gtk, Notify

from gripboard.scanner import ScanResult, Severity

_MAX_HISTORY = 20

_SEV_ICONS = {
    Severity.SAFE: "security-high",
    Severity.LOW: "security-medium",
    Severity.MEDIUM: "security-medium",
    Severity.HIGH: "security-low",
    Severity.CRITICAL: "security-low",
}


class TrayApp:
    """System tray application for Gripboard."""

    def __init__(self, on_toggle: callable = None, on_quit: callable = None):
        self._monitoring = True
        self._on_toggle = on_toggle
        self._on_quit = on_quit
        self._history: list[tuple[str, ScanResult]] = []

        Notify.init("Gripboard")

        self._indicator = AppIndicator3.Indicator.new(
            "gripboard",
            "security-high",
            AppIndicator3.IndicatorCategory.SYSTEM_SERVICES,
        )
        self._indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)
        self._indicator.set_title("Gripboard")

        self._build_menu()

    def _build_menu(self) -> None:
        menu = Gtk.Menu()

        # Status item
        self._status_item = Gtk.MenuItem(label="Status: Monitoring")
        self._status_item.set_sensitive(False)
        menu.append(self._status_item)

        menu.append(Gtk.SeparatorMenuItem())

        # Toggle monitoring
        self._toggle_item = Gtk.MenuItem(label="Pause Monitoring")
        self._toggle_item.connect("activate", self._on_toggle_clicked)
        menu.append(self._toggle_item)

        menu.append(Gtk.SeparatorMenuItem())

        # Recent findings submenu
        self._history_item = Gtk.MenuItem(label="Recent Findings")
        self._history_menu = Gtk.Menu()
        no_findings = Gtk.MenuItem(label="No findings yet")
        no_findings.set_sensitive(False)
        self._history_menu.append(no_findings)
        self._history_item.set_submenu(self._history_menu)
        menu.append(self._history_item)

        menu.append(Gtk.SeparatorMenuItem())

        # Quit
        quit_item = Gtk.MenuItem(label="Quit")
        quit_item.connect("activate", self._on_quit_clicked)
        menu.append(quit_item)

        menu.show_all()
        self._indicator.set_menu(menu)

    def _on_toggle_clicked(self, _widget) -> None:
        self._monitoring = not self._monitoring
        if self._monitoring:
            self._toggle_item.set_label("Pause Monitoring")
            self._status_item.set_label("Status: Monitoring")
            self._indicator.set_icon_full("security-high", "Monitoring")
        else:
            self._toggle_item.set_label("Resume Monitoring")
            self._status_item.set_label("Status: Paused")
            self._indicator.set_icon_full("security-low", "Paused")

        if self._on_toggle:
            self._on_toggle(self._monitoring)

    def _on_quit_clicked(self, _widget) -> None:
        if self._on_quit:
            self._on_quit()
        Notify.uninit()
        Gtk.main_quit()

    @property
    def is_monitoring(self) -> bool:
        return self._monitoring

    def push_result(self, result: ScanResult) -> None:
        """Push a scan result to the tray history (thread-safe via GLib.idle_add)."""
        GLib.idle_add(self._push_result_main, result)

    def _push_result_main(self, result: ScanResult) -> bool:
        if result.is_clean:
            return False

        # Update icon to reflect threat level
        icon = _SEV_ICONS.get(result.severity, "security-medium")
        self._indicator.set_icon_full(icon, result.severity.value)

        # Add to history
        preview = result.content[:60].replace("\n", " ")
        if len(result.content) > 60:
            preview += "..."
        self._history.append((preview, result))
        if len(self._history) > _MAX_HISTORY:
            self._history.pop(0)

        # Rebuild history submenu
        self._rebuild_history_menu()

        # Desktop notification
        self._send_notification(result)

        # Reset icon after 5 seconds
        GLib.timeout_add_seconds(5, self._reset_icon)

        return False  # GLib.idle_add: don't repeat

    def _rebuild_history_menu(self) -> None:
        new_menu = Gtk.Menu()
        for preview, res in reversed(self._history):
            sev = res.severity.value.upper()
            count = len(res.findings)
            label = f"[{sev}] ({count} finding{'s' if count != 1 else ''}) {preview}"
            item = Gtk.MenuItem(label=label[:80])
            item.set_sensitive(False)
            new_menu.append(item)
        new_menu.show_all()
        self._history_item.set_submenu(new_menu)

    def _send_notification(self, result: ScanResult) -> None:
        sev = result.severity
        urgency = (
            Notify.Urgency.CRITICAL
            if sev in (Severity.HIGH, Severity.CRITICAL)
            else Notify.Urgency.NORMAL
        )

        summary = f"Gripboard: {sev.value.upper()} alert"
        body = f"{len(result.findings)} suspicious character(s) in clipboard."
        if result.findings:
            body += f"\n{result.findings[0].description}"

        notif = Notify.Notification.new(summary, body, _SEV_ICONS.get(sev, "dialog-warning"))
        notif.set_urgency(urgency)
        try:
            notif.show()
        except GLib.Error:
            pass

    def _reset_icon(self) -> bool:
        if self._monitoring:
            self._indicator.set_icon_full("security-high", "Monitoring")
        return False  # don't repeat

    def run(self) -> None:
        """Start the GTK main loop (blocking)."""
        Gtk.main()

    def quit(self) -> None:
        """Quit from any thread."""
        GLib.idle_add(Gtk.main_quit)
