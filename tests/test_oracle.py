"""Tests for the context-aware XSS oracle.

Run:  pytest -q      (from the repo root)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

import oracle  # noqa: E402

MARKER = oracle.MARKER
PAYLOAD = f'{MARKER}"><svg/onload=alert(1)>'


def test_body_context_exploitable():
    html = f"<html><body><p>Hello {PAYLOAD}</p></body></html>"
    f = oracle.analyze(html, PAYLOAD)
    assert f["context"] == "HTML_BODY"
    assert f["reflected"] and f["raw_reflected"]
    assert f["exploitable"]
    assert f["severity"] == "HIGH"


def test_attribute_context_exploitable():
    html = f'<input type="text" value="{MARKER}" onx="{PAYLOAD}">'
    f = oracle.analyze(html, PAYLOAD)
    assert f["context"] in ("HTML_ATTRIBUTE", "EVENT_HANDLER")
    assert f["exploitable"]


def test_script_context_is_critical():
    html = f'<script>var a = "{PAYLOAD}";</script>'
    f = oracle.analyze(html, PAYLOAD)
    assert f["context"] == "SCRIPT"
    assert f["exploitable"]
    assert f["severity"] == "CRITICAL"


def test_event_handler_is_critical():
    needle = f'{MARKER}" '
    html = f'<div onclick="doThing({MARKER})" title="{needle}">x</div>'
    # locator ARC_9f3k2 appears in onclick attr -> event handler
    html = f'<button onclick="go(\'{MARKER}\')">b</button>'
    f = oracle.analyze(html, MARKER)
    assert f["context"] == "EVENT_HANDLER"


def test_url_attribute_context():
    html = f'<a href="{MARKER}">link</a>'
    f = oracle.analyze(html, MARKER)
    assert f["context"] == "URL_ATTRIBUTE"


def test_escaped_is_safe_negative_control():
    import html as h
    html_text = f"<p>value: {h.escape(PAYLOAD, quote=True)}</p>"
    f = oracle.analyze(html_text, PAYLOAD)
    assert f["safely_escaped"] is True
    assert f["exploitable"] is False
    assert f["severity"] == "SAFE"


def test_not_found():
    f = oracle.analyze("<p>nothing here</p>", PAYLOAD)
    assert f["context"] == "NOT_FOUND"
    assert f["reflected"] is False


def test_plain_marker_reflected_but_not_proven_exploitable():
    html = f"<p>{MARKER}</p>"
    f = oracle.analyze(html, MARKER)
    assert f["reflected"] is True
    assert f["exploitable"] is False
    assert f["severity"] == "LOW"


def test_comment_context():
    html = f"<!-- note: {MARKER} -->"
    f = oracle.analyze(html, MARKER)
    assert f["context"] == "HTML_COMMENT"


def test_remediation_present():
    html = f"<script>var a='{PAYLOAD}'</script>"
    f = oracle.analyze(html, PAYLOAD)
    assert f["remediation"]["title"]
    assert f["remediation"]["fix"]
