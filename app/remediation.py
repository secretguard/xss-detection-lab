"""
Context-specific remediation advice - the "Response" phase of the
Attack -> Evidence -> Detection -> Response flow.

The whole point of detecting the *context* (and not just "input reflected")
is that the correct fix is different in each one. This module turns a context
into concrete, actionable guidance shown on the dashboard next to every
finding.
"""

from __future__ import annotations

_ADVICE = {
    "SCRIPT": {
        "title": "Input reflected inside a <script> block",
        "detail": (
            "The value lands directly in executable JavaScript. An attacker "
            "does not even need HTML tags - they can close the string/statement "
            "and run code. This is the most dangerous context."
        ),
        "fix": (
            "Never build script from untrusted input. Pass data to JS via a "
            "JSON-encoded data attribute or <script type=\"application/json\"> "
            "block and read it with JSON.parse. If you must inline it, use a "
            "strict JSON serializer and a Content-Security-Policy that forbids "
            "inline script."
        ),
        "code": 'el.dataset.value = userInput;  // then read in JS, never concatenate',
    },
    "EVENT_HANDLER": {
        "title": "Input reflected inside an event-handler attribute (onclick, onload, ...)",
        "detail": (
            "Event-handler attributes are JavaScript execution contexts. Any "
            "reflected value here runs as code when the event fires."
        ),
        "fix": (
            "Remove inline event handlers entirely. Attach behaviour with "
            "addEventListener in a separate, static script file and keep user "
            "data in data-* attributes."
        ),
        "code": 'btn.addEventListener("click", handler);  // no inline on* attributes',
    },
    "URL_ATTRIBUTE": {
        "title": "Input reflected inside a URL attribute (href, src, action, ...)",
        "detail": (
            "A reflected value in a URL attribute allows javascript: and data: "
            "URIs, which execute script on click/load, plus open-redirect abuse."
        ),
        "fix": (
            "Allow-list the scheme (http/https/mailto only), reject javascript: "
            "and data:, and URL-encode the value. Resolve against a known base "
            "URL before using it."
        ),
        "code": 'if (new URL(v, base).protocol not in ("http:", "https:")) reject(v)',
    },
    "HTML_ATTRIBUTE": {
        "title": "Input reflected inside an HTML attribute value",
        "detail": (
            "If the quote character is not escaped, the attacker closes the "
            "attribute and injects new attributes (e.g. an event handler) or a "
            "new tag."
        ),
        "fix": (
            "Always quote attributes and HTML-escape the value, encoding "
            "\" & < > and ' . Use your template engine's attribute escaping "
            "(e.g. Jinja autoescape) rather than hand-built strings."
        ),
        "code": 'value="{{ user_input }}"   # autoescaped: " -> &quot;',
    },
    "HTML_BODY": {
        "title": "Input reflected into the HTML body",
        "detail": (
            "If < and > survive unescaped, the attacker injects a <script> or an "
            "element with an event handler (e.g. <img onerror>) that executes."
        ),
        "fix": (
            "HTML-escape the value (< > & \" ') before inserting it as text, or "
            "set textContent instead of innerHTML on the client. For rich HTML, "
            "sanitize with a vetted library (DOMPurify / bleach) and an allow-list."
        ),
        "code": 'el.textContent = userInput;  // or escape() server-side',
    },
    "STYLE": {
        "title": "Input reflected inside a <style> block",
        "detail": (
            "CSS injection can exfiltrate data and, in older browsers, run "
            "script via expression()/url(). Lower severity but still unsafe."
        ),
        "fix": (
            "Do not reflect user input into CSS. If unavoidable, allow-list a "
            "small set of known-safe values; never pass raw input into url() or "
            "property values."
        ),
        "code": "/* use a fixed class, toggle it from JS - never inline user CSS */",
    },
    "HTML_COMMENT": {
        "title": "Input reflected inside an HTML comment",
        "detail": (
            "A payload containing --> closes the comment early and injects live "
            "markup after it."
        ),
        "fix": (
            "Never place untrusted input in comments. If you must, strip --> and "
            "HTML-escape the remainder."
        ),
        "code": "# drop user input from comments entirely",
    },
    "NOT_FOUND": {
        "title": "Input did not reflect",
        "detail": "The submitted value was not found in the response.",
        "fix": "No action needed - the input is not reflected on this response.",
        "code": "",
    },
}

_SAFE = {
    "title": "Reflected but safely neutralised",
    "detail": (
        "The value is present but its dangerous characters were HTML-escaped, "
        "so it cannot break out of its context. This is the fixed/expected "
        "state and is NOT a vulnerability (negative control)."
    ),
    "fix": "Keep this escaping in place. This is the correct behaviour.",
    "code": "",
}


def advise(context: str, severity: str) -> dict:
    """Return remediation guidance for a (context, severity) pair."""
    if severity == "SAFE":
        return dict(_SAFE)
    return dict(_ADVICE.get(context, _ADVICE["HTML_BODY"]))
