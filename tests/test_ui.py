"""Tests for the v2.0.0 interface layer.

Everything here is offline and deterministic: the menu is driven through
injected ``input_fn``/``output_fn`` callables, so no test needs a terminal, and
no test contacts a network host.
"""

import io
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.base import IsolatedHomeCase  # noqa: E402  - sets the env first

from core import ui  # noqa: E402
from core.ui import animation, boot, menu, theme, widgets  # noqa: E402
from core.ui.banner import (  # noqa: E402
    HEIGHT,
    banner as banner_text,
    prompt_string,
    render_word,
    wordmark,
)


class Harness:
    """Feeds a scripted list of answers and records everything printed."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.lines = []
        self.prompts = []

    def input(self, prompt=""):
        self.prompts.append(prompt)
        if not self.answers:
            raise EOFError
        return self.answers.pop(0)

    def output(self, text=""):
        self.lines.append(str(text))

    @property
    def text(self):
        return "\n".join(self.lines)


class ThemeCase(IsolatedHomeCase):
    def setUp(self):
        super().setUp()
        theme.reset_color_state()
        animation.reset_animation_state()

    def tearDown(self):
        theme.reset_color_state()
        animation.reset_animation_state()
        super().tearDown()

    # -- palette ---------------------------------------------------------- #
    def test_palette_constants_are_ansi(self):
        for name in ("BLOOD", "NEON_RED", "CRIMSON", "WHITE", "GREY", "GREEN"):
            value = getattr(theme, name)
            self.assertTrue(value.startswith("\033["), name)

    def test_color_disabled_returns_plain_text(self):
        theme.set_color(False)
        self.assertEqual(theme.c("hello", theme.BLOOD), "hello")

    def test_color_enabled_wraps_and_resets(self):
        theme.set_color(True)
        out = theme.c("hello", theme.BLOOD)
        self.assertTrue(out.startswith(theme.BLOOD))
        self.assertTrue(out.endswith(theme.RESET))

    def test_strip_ansi_removes_escapes(self):
        theme.set_color(True)
        self.assertEqual(theme.strip_ansi(theme.c("x", theme.BLOOD)), "x")

    def test_no_color_env_wins(self):
        theme.reset_color_state()
        os.environ["NO_COLOR"] = "1"
        try:
            self.assertFalse(theme.color_enabled())
        finally:
            os.environ.pop("NO_COLOR", None)


class AnimationCase(IsolatedHomeCase):
    def setUp(self):
        super().setUp()
        animation.reset_animation_state()

    def tearDown(self):
        animation.reset_animation_state()
        os.environ.pop("REAPER_NO_ANIM", None)
        super().tearDown()

    def test_disabled_when_not_a_tty(self):
        # The test runner's stdout is a pipe, so this is the real code path.
        self.assertFalse(animation.animations_enabled())

    def test_env_var_disables(self):
        os.environ["REAPER_NO_ANIM"] = "1"
        self.assertFalse(animation.animations_enabled())

    def test_forced_on(self):
        animation.set_animations(True)
        self.assertTrue(animation.animations_enabled())

    def test_sleep_is_noop_when_disabled(self):
        import time

        animation.set_animations(False)
        started = time.time()
        animation.sleep(0.5)
        self.assertLess(time.time() - started, 0.2)

    def test_progress_animation_prints_final_frame_when_disabled(self):
        animation.set_animations(False)
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            widgets.progress_animation(10, "scan")
        out = buffer.getvalue()
        self.assertIn("10/10", out)
        self.assertIn("scan", out)


class BannerCase(IsolatedHomeCase):
    def setUp(self):
        super().setUp()
        theme.set_color(False)

    def tearDown(self):
        theme.reset_color_state()
        super().tearDown()

    def test_wordmark_has_five_rows_per_word(self):
        rows = render_word("KING")
        self.assertEqual(len(rows), HEIGHT)

    def test_wordmark_contains_both_words(self):
        art = wordmark()
        self.assertEqual(len(art), HEIGHT * 2 + 1)

    def test_banner_mentions_brand_and_version(self):
        out = banner_text("2.0.0")
        self.assertIn("2.0.0", out)
        self.assertIn("ULTIMATE CYBER INTELLIGENCE", out)

    def test_compact_banner_is_narrow(self):
        out = banner_text("2.0.0", compact=True)
        self.assertIn("KING REAPER X", out)
        for line in out.splitlines():
            self.assertLessEqual(len(line), 60, line)

    def test_prompt_string(self):
        self.assertIn("REAPER-X", prompt_string())
        self.assertIn("TERMUX", prompt_string())


class MenuRenderCase(IsolatedHomeCase):
    def setUp(self):
        super().setUp()
        theme.set_color(False)

    def tearDown(self):
        theme.reset_color_state()
        super().tearDown()

    def test_sixteen_items_plus_exit(self):
        self.assertEqual(len(menu.MENU_ITEMS), 16)
        self.assertEqual(len(menu.all_keys()), 17)

    def test_every_key_is_two_digits(self):
        for item in menu.MENU_ITEMS:
            self.assertRegex(item.key, r"^\d{2}$")

    def test_main_menu_lists_every_label(self):
        out = menu.main_menu()
        for item in menu.MENU_ITEMS:
            self.assertIn(item.label, out)
        self.assertIn("[00]", out)

    def test_main_menu_marks_gated_entries(self):
        out = menu.main_menu()
        self.assertIn("⚿", out)

    def test_resolve_returns_item_for_every_key(self):
        for item in menu.MENU_ITEMS:
            self.assertIsNotNone(menu.resolve(item.key), item.key)

    def test_resolve_rejects_unknown(self):
        for bad in ("99", "17", "abc", "", "1"):
            self.assertIsNone(menu.resolve(bad), bad)

    def test_every_item_has_a_real_destination(self):
        """No dead menu entries: each row is a module, a sub-menu or a handler."""
        handled = {"12", "13", "14", "15"}
        for item in menu.MENU_ITEMS:
            self.assertTrue(
                item.module or item.submenu or item.key in handled,
                f"{item.key} {item.label} has no destination",
            )

    def test_every_module_entry_exists_in_registry(self):
        from core import registry

        names = {entry["name"] for entry in registry.discover() if entry.get("importable")}
        for item in menu.MENU_ITEMS:
            if item.module:
                self.assertIn(item.module, names, item.label)

    def test_module_menu_renders_known_submenus(self):
        for name in menu.SUBMENUS:
            out = menu.module_menu(name)
            self.assertIn(name.upper(), out)
            self.assertIn("[0]", out)

    def test_module_menu_unknown_is_empty(self):
        self.assertEqual(menu.module_menu("nope"), "")

    def test_submenu_entries_resolve(self):
        for name, items in menu.SUBMENUS.items():
            for item in items:
                self.assertIsNotNone(menu.resolve_submenu(name, item.key), f"{name}/{item.key}")


class MenuLoopCase(IsolatedHomeCase):
    def setUp(self):
        super().setUp()
        theme.set_color(False)
        animation.set_animations(False)

    def tearDown(self):
        theme.reset_color_state()
        animation.reset_animation_state()
        super().tearDown()

    def test_exit_key_returns_zero(self):
        h = Harness(["00"])
        self.assertEqual(menu.run_menu(h.input, h.output, boot=False), 0)
        self.assertIn("session closed", h.text)

    def test_eof_exits_cleanly(self):
        h = Harness([])
        self.assertEqual(menu.run_menu(h.input, h.output, boot=False), 0)

    def test_invalid_selection_warns_and_reprompts(self):
        h = Harness(["99", "abc", "00"])
        self.assertEqual(menu.run_menu(h.input, h.output, boot=False), 0)
        self.assertIn("not a menu option", h.text)
        self.assertEqual(len(h.prompts), 3)

    def test_ctrl_c_returns_to_menu(self):
        """A Ctrl+C raised inside a handler must not kill the console."""
        original = menu._dispatch

        def boom(*args, **kwargs):
            raise KeyboardInterrupt

        menu._dispatch = boom
        try:
            h = Harness(["12", "00"])
            self.assertEqual(menu.run_menu(h.input, h.output, boot=False), 0)
        finally:
            menu._dispatch = original
        self.assertIn("interrupted", h.text)

    def test_ctrl_c_at_prompt_exits_cleanly(self):
        """Ctrl+C while reading input is swallowed by _ask and exits cleanly."""

        def raising(prompt=""):
            raise KeyboardInterrupt

        h = Harness([])
        h.input = raising
        self.assertEqual(menu.run_menu(h.input, h.output, boot=False), 0)

    def test_status_entry_renders_dashboard(self):
        h = Harness(["12", "00"])
        menu.run_menu(h.input, h.output, boot=False)
        self.assertIn("COMMAND CENTRE", h.text)
        self.assertIn("MODULES", h.text)

    def test_history_entry_runs(self):
        h = Harness(["13", "00"])
        menu.run_menu(h.input, h.output, boot=False)
        self.assertTrue(h.text.strip())

    def test_providers_entry_runs(self):
        # cmd_config prints directly, so capture stdout rather than the harness.
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            h = Harness(["15", "00"])
            menu.run_menu(h.input, h.output, boot=False)
        self.assertIn("virustotal", buffer.getvalue().lower())

    def test_phone_submenu_rejects_empty_number(self):
        h = Harness(["01", "1", "", "00"])
        menu.run_menu(h.input, h.output, boot=False)
        self.assertIn("no number entered", h.text)

    def test_phone_submenu_renders_real_analysis(self):
        h = Harness(["01", "1", "+966501234567", "00"])
        menu.run_menu(h.input, h.output, boot=False)
        self.assertIn("PHONE INTELLIGENCE", h.text)
        self.assertIn("Saudi Arabia", h.text)
        self.assertIn("+966", h.text)
        self.assertIn("mobile", h.text)
        self.assertIn("FORMATS", h.text)
        self.assertIn("VALIDATION", h.text)

    def test_phone_enrichment_without_key_degrades(self):
        h = Harness(["01", "2", "+966501234567", "00"])
        menu.run_menu(h.input, h.output, boot=False)
        self.assertIn("CARRIER ENRICHMENT", h.text)
        # No numverify key in the isolated home: must say so, not invent a carrier.
        self.assertIn("numverify", h.text.lower())

    def test_gated_port_scan_requires_confirmation(self):
        h = Harness(["11", "127.0.0.1", "no", "00"])
        menu.run_menu(h.input, h.output, boot=False)
        self.assertIn("AUTHORIZATION REQUIRED", h.text)
        self.assertIn("authorization not confirmed", h.text)

    def test_settings_submenu_shows_config(self):
        h = Harness(["16", "1", "00"])
        menu.run_menu(h.input, h.output, boot=False)
        self.assertIn("SETTINGS", h.text)
        self.assertIn("timeout", h.text)

    def test_settings_toggle_color(self):
        from core.config import load_config

        before = load_config().get_bool("color", True)
        h = Harness(["16", "3", "00"])
        menu.run_menu(h.input, h.output, boot=False)
        self.assertNotEqual(load_config().get_bool("color", True), before)

    def test_module_entry_without_target_warns(self):
        h = Harness(["03", "", "00"])
        menu.run_menu(h.input, h.output, boot=False)
        self.assertIn("no target entered", h.text)


class BootCase(IsolatedHomeCase):
    def setUp(self):
        super().setUp()
        theme.set_color(False)
        animation.set_animations(False)

    def tearDown(self):
        theme.reset_color_state()
        animation.reset_animation_state()
        super().tearDown()

    def test_boot_checks_all_measured(self):
        results = boot.run_boot_checks()
        self.assertEqual(len(results), len(boot.BOOT_STEPS))
        for item in results:
            self.assertIn("step", item)
            self.assertIn("ok", item)
            self.assertIn("detail", item)
            self.assertTrue(item["detail"])

    def test_python_and_database_checks_pass(self):
        results = {item["step"]: item for item in boot.run_boot_checks()}
        self.assertTrue(results["Python environment"]["ok"])
        self.assertTrue(results["Database connection"]["ok"])

    def test_startup_animation_prints_ready(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            boot.startup_animation("2.0.0", clear=False)
        out = buffer.getvalue()
        self.assertIn("INITIALIZING SECURITY FRAMEWORK", out)
        self.assertIn("SYSTEM READY", out)
        self.assertIn("2.0.0", out)

    def test_dashboard_reports_real_counts(self):
        out = boot.system_dashboard()
        self.assertIn("COMMAND CENTRE", out)
        self.assertIn("total modules", out)
        self.assertIn("13", out)  # the registry really has 13 modules
        self.assertIn("CONNECTED", out)


class WidgetCase(IsolatedHomeCase):
    def setUp(self):
        super().setUp()
        theme.set_color(False)

    def tearDown(self):
        theme.reset_color_state()
        super().tearDown()

    def test_success_and_error_prefixes(self):
        self.assertTrue(widgets.display_success("ok").startswith("[+]"))
        self.assertTrue(widgets.display_error("bad").startswith("[x]"))

    def test_table_aligns_rows(self):
        out = widgets.table(["a", "b"], [["1", "2"], ["long", "x"]])
        lines = out.splitlines()
        self.assertEqual(len(lines), 4)

    def test_table_empty(self):
        self.assertIn("no results", widgets.table(["a"], []))

    def test_findings_sorted_worst_first(self):
        out = widgets.findings_block([
            {"severity": "low", "title": "minor"},
            {"severity": "critical", "title": "severe"},
        ])
        self.assertLess(out.index("severe"), out.index("minor"))

    def test_result_block_handles_failure(self):
        out = widgets.result_block({"ok": False, "error": "x", "message": "y"}, "m")
        self.assertIn("x: y", out)

    def test_result_block_handles_degraded(self):
        out = widgets.result_block(
            {"ok": True, "degraded": True, "message": "no key", "requires": "virustotal"}, "m"
        )
        self.assertIn("DEGRADED", out)
        self.assertIn("virustotal", out)

    def test_clear_terminal_silent_when_not_tty(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            widgets.clear_terminal()
        self.assertEqual(buffer.getvalue(), "")


class RequiredApiCase(IsolatedHomeCase):
    """The nine functions the spec names must exist and be callable."""

    def test_required_functions_exist(self):
        for name in (
            "display_banner",
            "startup_animation",
            "system_dashboard",
            "main_menu",
            "module_menu",
            "progress_animation",
            "display_success",
            "display_error",
            "clear_terminal",
        ):
            self.assertTrue(hasattr(ui, name), name)
            self.assertTrue(callable(getattr(ui, name)), name)

    def test_legacy_aliases_still_present(self):
        for name in ("banner", "success", "error", "warn", "info", "hint", "status_badge", "c", "table"):
            self.assertTrue(hasattr(ui, name), name)


if __name__ == "__main__":
    unittest.main()
