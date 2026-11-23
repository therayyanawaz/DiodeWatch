"""The wall's accessibility contract, asserted instead of assumed.

The components already carry the pieces: roles on the feed, the listbox and the
evidence dialog; `aria-label` on icon-only buttons; a skip link; Escape and
arrow keys wired in `Listbox.tsx` and `EvidenceDrawer.tsx`. Nothing checked that
they stayed, so a refactor could drop a label and every test would still pass.
These are the assertions that notice.

A judge demo runs on a projector with a keyboard and no mouse, which is why the
keyboard half is here and not left to a manual pass.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SHELLS = [REPO / "apps/mission_control/static/index.html",
          REPO / "apps/mission_control/static/status.html"]
COMPONENTS = sorted((REPO / "frontend" / "src").rglob("*.tsx"))
CSS = REPO / "apps/mission_control" / "static" / "css" / "app.css"

pytestmark = pytest.mark.skipif(not COMPONENTS, reason="frontend sources absent")


def _sources() -> list[tuple[Path, str]]:
    return [(p, p.read_text(encoding="utf-8")) for p in COMPONENTS]


def test_both_shells_declare_a_language_and_a_title():
    for shell in SHELLS:
        html = shell.read_text(encoding="utf-8")
        assert '<html lang="' in html, shell.name
        assert re.search(r"<title>[^<]+</title>", html), shell.name


def test_both_shells_offer_a_skip_link():
    """The wall opens on a dense dashboard; without this, keyboard focus starts
    at the top of a nav tree and a demo loses ten seconds to Tab."""
    for shell in SHELLS:
        html = shell.read_text(encoding="utf-8")
        assert re.search(r'<a class="skip" href="#\w+"', html), shell.name


def test_decorative_svg_is_hidden_from_the_accessibility_tree():
    for shell in SHELLS:
        html = shell.read_text(encoding="utf-8")
        if "<symbol" in html:
            assert 'aria-hidden="true"' in html, shell.name


BUTTON = re.compile(r"<button\b[^>]*>", re.DOTALL)
NAME_ATTR = re.compile(r'(aria-label|aria-labelledby|title)\s*=')


def test_every_button_has_an_accessible_name():
    """Icon-only buttons are the failure mode: `<button><svg/></button>` is
    announced as "button" and nothing else."""
    offenders = []
    for path, text in _sources():
        for match in BUTTON.finditer(text):
            tag = match.group(0)
            if NAME_ATTR.search(tag):
                continue
            # children up to the closing tag: text or a {expression} both name it
            close = text.find("</button>", match.end())
            body = text[match.end():close if close != -1 else match.end() + 400]
            if re.search(r"[A-Za-z0-9]", body) or "{" in body:
                continue
            offenders.append(f"{path.name}: {tag.splitlines()[0][:80]}")
    assert not offenders, "buttons with no accessible name:\n  " + "\n  ".join(offenders)


def test_interactive_roles_carry_a_name():
    """A role that takes no name from its contents has to be named explicitly.

    `tooltip` is the exception that proves the rule: it is not named at all, it
    is the *description* of the control that owns it, so the pairing to require
    is an `id` on the tip and an `aria-describedby` pointing at it.
    """
    role = re.compile(r'role="(listbox|dialog|feed|tooltip|menu|tablist)"[^>]*')
    offenders = []
    for path, text in _sources():
        for match in role.finditer(text):
            tag = match.group(0)
            if NAME_ATTR.search(tag):
                continue
            if match.group(1) == "tooltip":
                if "id=" in tag and "aria-describedby" in text:
                    continue
                offenders.append(f"{path.name}: tooltip not wired as a description: {tag[:60]}")
                continue
            # the label may sit on the element's own line block, a few lines on
            tail = text[match.end():match.end() + 240]
            if not NAME_ATTR.search(tail):
                offenders.append(f"{path.name}: {tag[:70]}")
    assert not offenders, "roles with no accessible name:\n  " + "\n  ".join(offenders)


def test_the_listbox_is_keyboard_operable():
    text = (REPO / "frontend/src/components/Listbox.tsx").read_text(encoding="utf-8")
    for key in ("Escape", "ArrowDown", "ArrowUp", "Enter"):
        assert key in text, f"listbox lost {key} handling"
    assert 'role="listbox"' in text and 'role="option"' in text
    assert "aria-expanded" in text and "aria-activedescendant" in text


def test_the_evidence_drawer_closes_on_escape():
    text = (REPO / "frontend/src/components/EvidenceDrawer.tsx").read_text(encoding="utf-8")
    assert '"Escape"' in text, "the drawer no longer closes on Escape"
    assert 'role="dialog"' in text


def test_no_focus_indicator_is_removed_without_a_replacement():
    """`outline: none` with nothing in its place is the classic regression: the
    element becomes invisible to anyone navigating by keyboard."""
    css = CSS.read_text(encoding="utf-8")
    blocks = re.findall(r"\{[^}]*\}", css)
    offenders = [b for b in blocks
                 if "outline: none" in b
                 and not re.search(r"box-shadow|border|background", b)]
    assert not offenders, f"focus removed with no replacement: {offenders}"


def test_a_global_focus_ring_exists():
    css = CSS.read_text(encoding="utf-8")
    assert re.search(r":focus-visible\s*\{[^}]*outline:", css), \
        "no global :focus-visible outline"
