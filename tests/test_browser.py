"""
Layer 4: Browser automation helper tests.
Uses MagicMock to simulate Playwright page/locator objects — no real browser launched.
"""
import pytest
from unittest.mock import MagicMock, patch, call

from command.browser_commands import (
    _fill_field,
    _find_password_field,
    _find_username_field,
    _submit_form,
    _discover_login_url,
    _poll_for_password,
    _poll_for_username,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _invisible_locator():
    """A locator whose first element is never visible."""
    loc = MagicMock()
    loc.first.is_visible.return_value = False
    loc.is_visible.return_value = False
    return loc


def _visible_locator():
    """A locator whose first element is visible."""
    loc = MagicMock()
    loc.first.is_visible.return_value = True
    loc.is_visible.return_value = True
    return loc


# ── _fill_field ───────────────────────────────────────────────────────────────

def test_fill_field_uses_fill_when_it_works():
    locator = MagicMock()
    locator.input_value.return_value = "correct_value"
    _fill_field(locator, "correct_value")
    locator.fill.assert_called_once_with("correct_value")
    locator.type.assert_not_called()


def test_fill_field_falls_back_to_type_when_fill_doesnt_register():
    locator = MagicMock()
    # fill() ran but the field still shows the wrong value (e.g. React-controlled input)
    locator.input_value.return_value = "old_value"
    _fill_field(locator, "new_value")
    locator.fill.assert_called_once_with("new_value")
    locator.clear.assert_called_once()
    locator.type.assert_called_once_with("new_value", delay=40)


def test_fill_field_clicks_field_first():
    locator = MagicMock()
    locator.input_value.return_value = "val"
    _fill_field(locator, "val")
    locator.click.assert_called_once()


def test_fill_field_handles_input_value_exception():
    locator = MagicMock()
    locator.input_value.side_effect = Exception("not supported")
    # Should not raise — the try/except in _fill_field swallows it
    _fill_field(locator, "value")
    locator.fill.assert_called_once_with("value")


# ── _poll_for_password (with time patched to expire immediately) ──────────────

def test_poll_for_password_returns_none_when_nothing_visible():
    page = MagicMock()
    invisible = _invisible_locator()
    page.get_by_role.return_value = invisible
    page.get_by_label.return_value = invisible
    page.locator.return_value = invisible

    # Make deadline expire after the first while-condition check
    with patch("command.browser_commands.time.monotonic", side_effect=[0.0, 999.0]):
        result = _poll_for_password(page, t_ms=2000)
    assert result is None


def test_poll_for_password_returns_locator_when_visible():
    page = MagicMock()
    visible = _visible_locator()
    page.get_by_role.return_value = visible
    page.get_by_label.return_value = _invisible_locator()
    page.locator.return_value = _invisible_locator()

    # Give enough "time" for one loop iteration
    with patch("command.browser_commands.time.monotonic", side_effect=[0.0, 0.5, 0.5, 999.0]):
        result = _poll_for_password(page, t_ms=2000)
    assert result is visible.first


# ── _find_password_field ──────────────────────────────────────────────────────

def test_find_password_field_returns_none_when_not_found():
    page = MagicMock()
    invisible = _invisible_locator()
    page.get_by_role.return_value = invisible
    page.get_by_label.return_value = invisible
    page.locator.return_value = invisible

    with patch("command.browser_commands.time.monotonic", side_effect=[0.0, 999.0, 0.0, 999.0]):
        result = _find_password_field(page)
    assert result is None


# ── _poll_for_username ────────────────────────────────────────────────────────

def test_poll_for_username_returns_none_when_nothing_visible():
    page = MagicMock()
    invisible = _invisible_locator()
    page.get_by_role.return_value = invisible
    page.get_by_label.return_value = invisible
    page.locator.return_value = invisible

    with patch("command.browser_commands.time.monotonic", side_effect=[0.0, 999.0]):
        result = _poll_for_username(page, t_ms=4000)
    assert result is None


def test_poll_for_username_returns_first_visible():
    page = MagicMock()
    visible = _visible_locator()
    page.get_by_role.return_value = visible
    page.get_by_label.return_value = _invisible_locator()
    page.locator.return_value = _invisible_locator()

    with patch("command.browser_commands.time.monotonic", side_effect=[0.0, 0.5, 0.5, 999.0]):
        result = _poll_for_username(page, t_ms=4000)
    assert result is visible.first


# ── _submit_form ──────────────────────────────────────────────────────────────

def test_submit_form_returns_true_when_button_found():
    page = MagicMock()
    visible = _visible_locator()
    page.get_by_role.return_value = visible
    assert _submit_form(page) is True
    visible.first.click.assert_called_once()


def test_submit_form_returns_false_when_no_button():
    page = MagicMock()
    invisible = _invisible_locator()
    page.get_by_role.return_value = invisible
    page.locator.return_value = invisible
    assert _submit_form(page) is False


def test_submit_form_falls_back_to_css_selector():
    page = MagicMock()
    invisible = _invisible_locator()
    # Semantic locators (get_by_role) all return invisible
    page.get_by_role.return_value = invisible
    # CSS locator is visible
    visible = _visible_locator()
    page.locator.return_value = visible

    assert _submit_form(page) is True


# ── _discover_login_url ───────────────────────────────────────────────────────

def test_discover_login_url_follows_signin_link():
    page = MagicMock()
    page.url = "https://example.com/login"
    visible = _visible_locator()
    page.get_by_role.return_value = visible

    result = _discover_login_url(page)
    assert result == "https://example.com/login"
    visible.first.click.assert_called_once()
    page.wait_for_load_state.assert_called_once_with("domcontentloaded", timeout=15_000)


def test_discover_login_url_returns_none_when_no_link():
    page = MagicMock()
    invisible = _invisible_locator()
    page.get_by_role.return_value = invisible
    page.locator.return_value = invisible

    result = _discover_login_url(page)
    assert result is None
