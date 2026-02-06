"""Confirmation dialog shown when suspicious clipboard content is detected."""

import gi

gi.require_version("Gtk", "3.0")

from gi.repository import GLib, Gtk, Pango

from gripboard.scanner import ScanResult, Severity

_SEV_COLORS = {
    Severity.LOW: "#b8860b",
    Severity.MEDIUM: "#cc7700",
    Severity.HIGH: "#cc0000",
    Severity.CRITICAL: "#880000",
}


class PasteAction:
    ALLOW = "allow"
    SANITIZE = "sanitize"
    BLOCK = "block"


def show_confirmation_dialog(result: ScanResult, sanitized: str | None = None) -> str:
    """Show a blocking GTK dialog and return the user's chosen action.

    Must be called from the GTK main thread (use GLib.idle_add if needed).

    Returns one of PasteAction.ALLOW, PasteAction.SANITIZE, PasteAction.BLOCK.
    """
    action = [PasteAction.BLOCK]  # default if dialog is closed

    dialog = Gtk.Dialog(
        title="Gripboard - Suspicious Clipboard Content",
        modal=True,
        destroy_with_parent=True,
    )
    dialog.set_default_size(600, 450)
    dialog.set_resizable(True)
    dialog.set_keep_above(True)
    dialog.set_position(Gtk.WindowPosition.CENTER)

    content_area = dialog.get_content_area()
    content_area.set_spacing(12)
    content_area.set_margin_start(16)
    content_area.set_margin_end(16)
    content_area.set_margin_top(12)
    content_area.set_margin_bottom(8)

    # --- Severity banner ---
    sev = result.severity
    color = _SEV_COLORS.get(sev, "#cc0000")
    banner = Gtk.Label()
    banner.set_markup(
        f'<span size="large" weight="bold" foreground="{color}">'
        f'  {sev.value.upper()} — Suspicious content detected</span>'
    )
    banner.set_halign(Gtk.Align.START)
    content_area.pack_start(banner, False, False, 0)

    # --- Finding summary ---
    summary = Gtk.Label(
        label=f"{len(result.findings)} suspicious character(s) found in clipboard content."
    )
    summary.set_halign(Gtk.Align.START)
    content_area.pack_start(summary, False, False, 0)

    # --- Findings list ---
    findings_frame = Gtk.Frame(label="Findings")
    scroll = Gtk.ScrolledWindow()
    scroll.set_min_content_height(120)
    scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

    findings_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    findings_box.set_margin_start(8)
    findings_box.set_margin_end(8)
    findings_box.set_margin_top(4)
    findings_box.set_margin_bottom(4)

    for f in result.findings[:25]:
        fc = _SEV_COLORS.get(f.severity, "#333")
        label = Gtk.Label()
        label.set_markup(
            f'<span foreground="{fc}" weight="bold">[{f.severity.value.upper()}]</span> '
            f"pos {f.position}: {GLib.markup_escape_text(f.codepoint)} — "
            f"{GLib.markup_escape_text(f.description)}"
        )
        label.set_halign(Gtk.Align.START)
        label.set_line_wrap(True)
        findings_box.pack_start(label, False, False, 0)

    if len(result.findings) > 25:
        more = Gtk.Label(label=f"... and {len(result.findings) - 25} more")
        more.set_halign(Gtk.Align.START)
        findings_box.pack_start(more, False, False, 0)

    scroll.add(findings_box)
    findings_frame.add(scroll)
    content_area.pack_start(findings_frame, True, True, 0)

    # --- Content preview ---
    preview_frame = Gtk.Frame(label="Clipboard Content (raw)")
    preview_scroll = Gtk.ScrolledWindow()
    preview_scroll.set_min_content_height(80)
    preview_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

    preview_text = Gtk.TextView()
    preview_text.set_editable(False)
    preview_text.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
    preview_text.set_monospace(True)
    buf = preview_text.get_buffer()
    # Show repr so invisible chars are visible
    display = repr(result.content[:2000])
    buf.set_text(display)
    preview_scroll.add(preview_text)
    preview_frame.add(preview_scroll)
    content_area.pack_start(preview_frame, True, True, 0)

    # --- Sanitized preview (if available) ---
    if sanitized is not None:
        san_frame = Gtk.Frame(label="Sanitized Version")
        san_scroll = Gtk.ScrolledWindow()
        san_scroll.set_min_content_height(60)
        san_scroll.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)

        san_text = Gtk.TextView()
        san_text.set_editable(False)
        san_text.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        san_text.set_monospace(True)
        san_buf = san_text.get_buffer()
        san_buf.set_text(sanitized[:2000])
        san_scroll.add(san_text)
        san_frame.add(san_scroll)
        content_area.pack_start(san_frame, False, True, 0)

    # --- Action buttons ---
    block_btn = dialog.add_button("Block Paste", Gtk.ResponseType.REJECT)
    block_btn.get_style_context().add_class("destructive-action")

    if sanitized is not None:
        dialog.add_button("Use Sanitized", Gtk.ResponseType.APPLY)

    allow_btn = dialog.add_button("Allow Anyway", Gtk.ResponseType.ACCEPT)

    dialog.set_default_response(Gtk.ResponseType.REJECT)

    content_area.show_all()

    response = dialog.run()
    dialog.destroy()

    # Process any pending GTK events so the dialog fully closes
    while Gtk.events_pending():
        Gtk.main_iteration()

    if response == Gtk.ResponseType.ACCEPT:
        return PasteAction.ALLOW
    elif response == Gtk.ResponseType.APPLY:
        return PasteAction.SANITIZE
    else:
        return PasteAction.BLOCK
