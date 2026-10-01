"""
Context-aware XSS reflection oracle.

This is a real HTML parser based detector (uses the standard library
``html.parser``, exactly as the project brief recommends) rather than the
fragile ``str.find()`` / substring approach used in the original prototype.

Given a response body and the string that was submitted to the target, it
answers three questions the original code could not answer reliably:

1. Did the input reflect, and is it reflected *raw* or only *HTML-escaped*?
2. In which **context** did it land - HTML body, an attribute value, an
   event-handler attribute, a URL attribute, a ``<script>`` block, a
   ``<style>`` block or an HTML comment?
3. Is it actually **exploitable** - i.e. did context-breaking characters
   (``< > " '``) survive unescaped so a payload could break out?

The answer drives severity grading and the context-specific remediation
advice in :mod:`remediation`.
"""

from __future__ import annotations

import html
import re
from html.parser import HTMLParser
from pathlib import Path

# A harmless, unique locator token. Picking something that never occurs
# naturally is how we find the input in a response without false matches.
MARKER = "ARC_9f3k2"

# Attribute names that mean "this value becomes executable / navigable".
_EVENT_ATTR = re.compile(r"^on", re.IGNORECASE)
_URL_ATTRS = {
    "href", "src", "action", "formaction", "data",
    "poster", "xlink:href", "background", "cite",
}

# Characters an attacker needs to break out of a context.
_BREAKOUT_CHARS = set('<>"\'`')


class _ContextLocator(HTMLParser):
    """Walk the document and record every context the locator lands in."""

    def __init__(self, locator: str):
        super().__init__(convert_charrefs=True)
        self.locator = locator
        self.hits: list[tuple[str, str]] = []
        self._in_script = False
        self._in_style = False

    # -- tags -----------------------------------------------------------
    def handle_starttag(self, tag, attrs):
        for name, value in attrs:
            if value and self.locator in value:
                lname = name.lower()
                if _EVENT_ATTR.match(lname):
                    ctx = "EVENT_HANDLER"
                elif lname in _URL_ATTRS:
                    ctx = "URL_ATTRIBUTE"
                else:
                    ctx = "HTML_ATTRIBUTE"
                self.hits.append((ctx, f'<{tag} {name}="...">'))
        if tag == "script":
            self._in_script = True
        elif tag == "style":
            self._in_style = True

    def handle_startendtag(self, tag, attrs):
        # self-closing tag, e.g. <input .../> - still check its attributes
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag):
        if tag == "script":
            self._in_script = False
        elif tag == "style":
            self._in_style = False

    # -- content --------------------------------------------------------
    def handle_data(self, data):
        if self.locator not in data:
            return
        if self._in_script:
            self.hits.append(("SCRIPT", "<script> ... </script>"))
        elif self._in_style:
            self.hits.append(("STYLE", "<style> ... </style>"))
        else:
            self.hits.append(("HTML_BODY", "text node between tags"))

    def handle_comment(self, data):
        if self.locator in data:
            self.hits.append(("HTML_COMMENT", "<!-- ... -->"))


# Severity when a context-breaking payload survives unescaped.
_SEVERITY = {
    "SCRIPT": "CRITICAL",
    "EVENT_HANDLER": "CRITICAL",
    "URL_ATTRIBUTE": "HIGH",
    "HTML_ATTRIBUTE": "HIGH",
    "HTML_BODY": "HIGH",
    "STYLE": "MEDIUM",
    "HTML_COMMENT": "MEDIUM",
}

# Order used when the input lands in more than one context at once.
_CONTEXT_PRIORITY = [
    "SCRIPT", "EVENT_HANDLER", "URL_ATTRIBUTE",
    "HTML_ATTRIBUTE", "HTML_BODY", "STYLE", "HTML_COMMENT",
]


def _locator(value: str) -> str:
    """Pick an alphanumeric token that survives both raw and escaped
    reflection - used purely to *locate* the input in the DOM.

    Preference order:
      1. the known MARKER, if the submitted value contains it;
      2. the leading alphanumeric run (attackers usually put the marker first,
         then the context-breaking characters);
      3. the longest alphanumeric token as a last resort.

    This avoids picking an injected keyword (e.g. "onmouseover") over the
    actual marker.
    """
    if MARKER in value:
        return MARKER
    lead = re.match(r"[A-Za-z0-9_]+", value)
    if lead and len(lead.group()) >= 4:
        return lead.group()
    tokens = re.findall(r"[A-Za-z0-9_]+", value)
    return max(tokens, key=len) if tokens else value


def analyze(response_html: str, submitted: str = MARKER) -> dict:
    """Analyse ``response_html`` for a reflection of ``submitted``.

    Returns a finding dict. The ``reflected`` / ``context`` /
    ``safely_escaped`` keys are kept for backwards compatibility with the
    original ``oracle.py`` CLI; the richer keys drive the live dashboard.
    """
    submitted = submitted or MARKER
    locator = _locator(submitted)

    raw_present = submitted in response_html
    escaped_form = html.escape(submitted, quote=True)
    escaped_present = escaped_form != submitted and escaped_form in response_html
    # The locator (alphanumeric) is found whether the payload was escaped or
    # not, so it tells us the *context* even on a safe page.
    locator_present = locator in response_html

    if not (raw_present or escaped_present or locator_present):
        return _finding(submitted, locator, reflected=False, raw=False,
                        escaped=False, context="NOT_FOUND",
                        detail="input not found in response",
                        exploitable=False, severity="NONE")

    # Locate the context(s) the input landed in.
    parser = _ContextLocator(locator)
    try:
        parser.feed(response_html)
        parser.close()
    except Exception:  # malformed markup should never crash detection
        pass

    if parser.hits:
        contexts = {c for c, _ in parser.hits}
        context = next((c for c in _CONTEXT_PRIORITY if c in contexts),
                       parser.hits[0][0])
        detail = next(d for c, d in parser.hits if c == context)
    else:
        context = "HTML_BODY"
        detail = "text node between tags"

    # Did the attacker-controlled breakout characters survive unescaped?
    submitted_has_breakout = bool(_BREAKOUT_CHARS & set(submitted))
    exploitable = raw_present and submitted_has_breakout

    if raw_present and submitted_has_breakout:
        severity = _SEVERITY.get(context, "MEDIUM")
    elif escaped_present and not raw_present:
        severity = "SAFE"       # reflected but neutralised - the fixed state
    elif raw_present:
        severity = "LOW"        # reflected, but no breakout chars proven yet
    else:
        severity = "SAFE"

    safely_escaped = escaped_present and not (raw_present and submitted_has_breakout)
    reflected = raw_present or escaped_present

    return _finding(submitted, locator, reflected=reflected, raw=raw_present,
                    escaped=safely_escaped, context=context, detail=detail,
                    exploitable=exploitable, severity=severity)


def _finding(submitted, locator, *, reflected, raw, escaped, context,
             detail, exploitable, severity) -> dict:
    from remediation import advise  # local import avoids a cycle at import time

    return {
        "needle": submitted,
        "locator": locator,
        "reflected": reflected,
        "raw_reflected": raw,
        "safely_escaped": escaped,   # legacy key name, kept intentionally
        "context": context,
        "context_detail": detail,
        "exploitable": exploitable,
        "severity": severity,
        "remediation": advise(context, severity),
    }


# A realistic payload (marker + context-breaking characters) used by the
# bundled sample files, so the negative control can tell escaped from raw.
DEMO_PAYLOAD = f'{MARKER}"><svg/onload=alert(1)>'


def _pick_needle(html_text: str) -> str:
    """Choose a sensible needle for a saved file when none is given.

    If the file contains the full demo payload (raw or escaped) use that so the
    negative control works; otherwise fall back to the plain marker, matching
    the assignment's ``python oracle.py body_context.html`` workflow.
    """
    if DEMO_PAYLOAD in html_text or html.escape(DEMO_PAYLOAD, quote=True) in html_text:
        return DEMO_PAYLOAD
    return MARKER


# ----------------------------------------------------------------------
# CLI - preserves the original workflow: analyse saved evidence files.
#   python oracle.py body_context.html
# ----------------------------------------------------------------------
def analyze_file(filename, needle: str | None = None) -> dict | None:
    path = Path(filename)
    if not path.exists():
        print(f"File not found: {filename}")
        return None
    html_text = path.read_text(encoding="utf-8", errors="replace")
    if needle is None:
        needle = _pick_needle(html_text)
    result = analyze(html_text, needle)
    print(f"\nFile:           {path.name}")
    print(f"Looking for:    {needle}")
    print(f"Context:        {result['context']}  ({result['context_detail']})")
    print(f"Reflected:      {result['reflected']}")
    print(f"Raw reflected:  {result['raw_reflected']}")
    print(f"Safely escaped: {result['safely_escaped']}")
    print(f"Exploitable:    {result['exploitable']}")
    print(f"Severity:       {result['severity']}")
    return result


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 2 and sys.argv[1] == "--needle":
        needle = sys.argv[2]
        for arg in sys.argv[3:]:
            analyze_file(arg, needle)
    elif len(sys.argv) > 1:
        for arg in sys.argv[1:]:
            analyze_file(arg)          # auto-detect the needle per file
    else:
        # Default: run the bundled samples (body / attribute / script / escaped).
        samples = Path(__file__).resolve().parent.parent / "samples"
        for name in ("body_context.html", "attribute_context.html",
                     "script_context.html", "escaped_context.html"):
            analyze_file(samples / name)
